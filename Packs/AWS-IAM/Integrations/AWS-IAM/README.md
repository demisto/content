<!-- HTML_DOC -->
<p> Use this integration to manage identity and access on the AWS platform.</p>
<p>We recommend that you use roles that have the following bulit-in AWS policies:</p>
<ul>
<li><em>IAMFullAccess</em></li>
<li><em>IAMReadOnlyAccess</em></li>
</ul>
<h2>Prerequisites</h2>
<p>It is important that you familiarize yourself with and complete all steps detailed in the <a href="https://support.demisto.com/hc/en-us/articles/360005686854">Amazon AWS Integrations Configuration Guide</a>.</p>
<h2>Configure the AWS IAM Integration on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for AWS - IAM.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>Role Arn</strong></li>
<li><strong>Role Session Name</strong></li>
<li><strong>Role Session Duration</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and token.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_35292443731528637122687">Create a user: aws-iam-create-user</a></li>
<li><a href="#h_761129142021528637130698">Get user information: aws-iam-get-user</a></li>
<li><a href="#h_6704055334001528637140705">Get a list of users: aws-iam-list-users</a></li>
<li><a href="#h_6229078945971528637153805">Update user information: aws-iam-update-user</a></li>
<li><a href="#h_1795381047931528637161312">Delete a user: aws-iam-delete-user</a></li>
<li><a href="#h_9675841759881528637170870">Update a user's password: aws-iam-login-profile</a></li>
<li><a href="#h_1791759411821528637182410">Create a group: aws-iam-create-group</a></li>
<li><a href="#h_37050694513751528637189851">Get a list of groups: aws-iam-list-groups</a></li>
<li><a href="#h_68797095715671528637200585">List all groups a user is part of: aws-iam-list-groups-for-user</a></li>
<li><a href="#h_35662279917581528637214561">Add a user to a group: aws-iam-add-user-to-group</a></li>
<li><a href="#h_27602886719481528637231351">Create an access key: aws-iam-create-access-key</a></li>
<li><a href="#h_30007538321371528637244497">Update an access key: aws-iam-update-access-key</a></li>
<li><a href="#h_43284584023251528637254677">List all access keys for a user: aws-iam-list-access-keys-for-user</a></li>
<li><a href="#h_89191343625121528637264663">List all policies: aws-iam-list-policies</a></li>
<li><a href="#h_93376955526981528637273805">List all roles: aws-iam-list-roles</a></li>
<li><a href="#h_72460316628831528637288904">Attach a policy to an entity: aws-iam-attach-policy</a></li>
<li><a href="#h_17675231430671528637303943">Detach a policy from an entity: aws-iam-detach-policy</a></li>
<li><a href="#h_79183429632501528637313930">Delete a user's password: aws-iam-delete-login-profile</a></li>
<li><a href="#h_79642664334321528637357663">Delete a group: aws-iam-delete-group</a></li>
<li><a href="#h_73326683936131528637368111">Remove a user from a group: aws-iam-remove-user-from-group</a></li>
<li><a href="#h_94886199837931528637386867">Create a password for a user: aws-iam-create-login-profile</a></li>
<li><a href="#h_27322833539721528637413111">Delete an access key: aws-iam-delete-access-key</a></li>
<li><a href="#h_22936187241501528637423630">Create an instance profile: aws-iam-create-instance-profile</a></li>
<li><a href="#h_90148501343271528637443566">Delete an instance profile: aws-iam-delete-instance-profile</a></li>
<li><a href="#h_85594047945031528637461268">List all instance profiles: aws-iam-list-instance-profiles</a></li>
<li><a href="#h_77573672846781528637536532">Add a role to an instance profile: aws-iam-add-role-to-instance-profile</a></li>
<li><a href="#h_99899176648521528637548087">Remove a role from an instance profile: aws-iam-remove-role-from-instance-profile</a></li>
<li><a href="#h_65709856051921528637588394">List all instance profiles for a role: aws-iam-list-instance-profiles-for-role</a></li>
<li><a href="#h_64652386953641528637606870">Get instance profile information: aws-iam-get-instance-profile</a></li>
<li><a href="#h_90184122455351528637618510">Get role information: aws-iam-get-role</a></li>
<li><a href="#h_70526274457051528637627532">Delete a role: aws-iam-delete-role</a></li>
<li><a href="#h_74037147358741528637636496">Create a role: aws-iam-create-role</a></li>
<li><a href="#h_6231318754001544460248411">Create a policy: aws-iam-create-policy</a></li>
<li><a href="#h_3523892546431544460254180">Delete a policy: aws-iam-delete-policy</a></li>
<li><a href="#h_5115172778831544460258719">Create a new version of a policy: aws-iam-create-policy-version</a></li>
<li><a href="#h_83948698411241544460263116">Delete a version of a policy: aws-iam-delete-policy-version</a></li>
<li><a href="#h_30437568018241544460273321">Get information for all versions of a policy: aws-iam-list-policy-versions</a></li>
<li><a href="#h_16892468322931544460281747">Get information for a policy version: aws-iam-get-policy-version</a></li>
<li><a href="#h_87933834125311544460287721">Set a default (operative) policy version: aws-iam-set-default-policy-version</a></li>
<li><a href="#h_34904695527661544460299590">Create an account alias: aws-iam-create-account-alias</a></li>
<li><a href="#h_41">Delete an account alias: aws-iam-delete-account-alias</a></li>
</ol>
<h3 id="h_35292443731528637122687">1. Create a user</h3>
<hr>
<p>Creates a user in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-create-user userName=Test path=/testusers/</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:CreateUser</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">userName</td>
<td style="width: 535px;">Name of the user to create</td>
</tr>
<tr>
<td style="width: 179px;">path</td>
<td style="width: 535px;">Path for the username. This parameter is optional. If it is not included in the command, it defaults to a forward slash (/).</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 63px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSetsChange.Id</td>
<td style="width: 503px;">Request ID</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSetsChange.Status</td>
<td style="width: 503px;">Current state of the request. PENDING indicates that the request has not yet been applied to all Amazon Route 53 DNS servers.</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSetsChange.Comment</td>
<td style="width: 503px;">A complex type that describes change information about changes made to your hosted zone.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "Arn":"arn:aws:iam::123456789:user/testusers/Test2",
   "CreateDate":"2018-06-04T12:12:20",
   "Path":"/testusers/",
   "UserId":"AIDSECGFSTGLFJWJXSXMC",
   "UserName":"Test2"
}
</pre>
<h3 id="h_761129142021528637130698">2. Get user information</h3>
<hr>
<p>Returns information about a user in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-get-user userName=test</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:GetUser</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">userName</td>
<td style="width: 535px;">Name of the user to create</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 63px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Users.UserName</td>
<td style="width: 503px;">Friendly name to identify the user</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Users.UserId</td>
<td style="width: 503px;">stable and unique string identifying the user</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Users.Arn</td>
<td style="width: 503px;">Amazon Resource Name (ARN) that identifies the user</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Users.CreateDate</td>
<td style="width: 503px;">Date and time when the user was created</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Users.Path</td>
<td style="width: 503px;">Path to the user</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Users.PasswordLastUsed</td>
<td style="width: 503px;">Date and time when the user's password was last used to sign in to an AWS website</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "Arn":"arn:aws:iam::123456789:user/testusers/Test",
   "CreateDate":"2018-06-04T12:11:20",
   "Path":"/testusers/",
   "UserId":"AIDASDADJDHKMTAUTCUZRQH26",
   "UserName":"Test"
}
</pre>
<h3 id="h_6704055334001528637140705">3. Get a list of users</h3>
<hr>
<p>Returns a list of all users in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-list-users</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:ListUsers</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 63px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Users.UserName</td>
<td style="width: 503px;">Friendly name to identify the user</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Users.UserId</td>
<td style="width: 503px;">Stable and unique string identifying the user</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Users.Arn</td>
<td style="width: 503px;">Amazon Resource Name (ARN) that identifies the user</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Users.CreateDate</td>
<td style="width: 503px;">Date and time when the user was created</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Users.Path</td>
<td style="width: 503px;">Path to the user</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "Arn":"arn:aws:iam::123456789:user/testusers/Test",
      "CreateDate":"2018-06-04 12:11:20",
      "Path":"/testusers/",
      "UserId":"AIDASFDASFSAJDHKMTAUTCUZRQH26",
      "UserName":"Test"
   },
   {  
      "Arn":"arn:aws:iam::123456789:user/testusers/Test2",
      "CreateDate":"2018-06-04 12:12:20",
      "Path":"/testusers/",
      "UserId":"AIDAI3Z2WTADFADGAGLFJWJXSXMC",
      "UserName":"Test2"
   }
]
</pre>
<h3 id="h_6229078945971528637153805">4. Update user information</h3>
<hr>
<p>Returns a list of all users in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-update-user oldUserName=test newUserName=NewUserName34 newPath=/iamtest/</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:UpdateUser</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">oldUserName</td>
<td style="width: 535px;">Name of the user to update</td>
</tr>
<tr>
<td style="width: 179px;">newUserName</td>
<td style="width: 535px;">New name for the user. Include this parameter only if you are changing the user's name.</td>
</tr>
<tr>
<td style="width: 179px;">newPath</td>
<td style="width: 535px;">New path for the user. Include this parameter only if you are changing the user's path.</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command. </p>
<h5>Raw Output</h5>
<pre>Changed UserName test To: NewUserName34
</pre>
<h3 id="h_1795381047931528637161312">5. Delete a user</h3>
<hr>
<p>Deletes a user from the the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-delete-user userName=userName34</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:DeleteUser</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">userName</td>
<td style="width: 535px;">Name of the user to delete</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command. </p>
<h5>Raw Output</h5>
<pre>The user <em>userName34</em> has been deleted
</pre>
<h3 id="h_9675841759881528637170870">6. Update a user's password</h3>
<hr>
<p>Update the password for a user in the the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-update-login-profile userName=userName34 newPassword=ArdVaEC@1#$F%g% passwordResetRequired=True raw-response=true</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:UpdateLoginProfile</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">userName</td>
<td style="width: 535px;">Name of the user you want to update the password for</td>
</tr>
<tr>
<td style="width: 179px;">newPassword</td>
<td style="width: 535px;">New password for the specified IAM user</td>
</tr>
<tr>
<td style="width: 179px;">passwordResetRequired</td>
<td style="width: 535px;">Specifies whether the user is required to set a new password on next sign in.</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command. </p>
<h5>Raw Output</h5>
<pre>The password for user <em>userName34</em> was changed.
</pre>
<h3 id="h_1791759411821528637182410">7. Create a group</h3>
<hr>
<p>Creates a group in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-create-group groupName=test path=/testgroups/</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:CreateGroup</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">groupName</td>
<td style="width: 535px;">Name of the group to create. Do not include the path in this value.</td>
</tr>
<tr>
<td style="width: 179px;">path</td>
<td style="width: 535px;">Path to the group</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 63px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Groups.GroupName</td>
<td style="width: 503px;">Friendly name to identify the group</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Groups.GroupId</td>
<td style="width: 503px;">Stable and unique string identifying the group</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Groups.Arn</td>
<td style="width: 503px;">Amazon Resource Name (ARN) that specifies the group</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Groups.CreateDate</td>
<td style="width: 503px;">Date and time when the group was created</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Groups.Path</td>
<td style="width: 503px;">Path to the group</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "Arn":"arn:aws:iam::123456789:group/testgroups/test",
   "CreateDate":"2018-06-04T13:32:34",
   "GroupId":"AGPAJH6IZW4TASFDUWDJVPQG",
   "GroupName":"test",
   "Path":"/testgroups/"
}
</pre>
<h3 id="h_37050694513751528637189851">8. Get a list of groups</h3>
<hr>
<p>Returns a list of all groups in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-list-groups</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:ListGroups</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 63px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Groups.GroupName</td>
<td style="width: 503px;">Friendly name to identify the group</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Groups.GroupId</td>
<td style="width: 503px;">Stable and unique string identifying the group</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Groups.Arn</td>
<td style="width: 503px;">Amazon Resource Name (ARN) that specifies the group</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Groups.CreateDate</td>
<td style="width: 503px;">Date and time when the group was created</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Groups.Path</td>
<td style="width: 503px;">Path to the group</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "Arn":"arn:aws:iam::123456789:group/Admins",
      "CreateDate":"2017-11-01T08:32:39",
      "GroupId":"AGPAJVFASADEZ5LCW",
      "GroupName":"Admins",
      "Path":"/"
   },
   {  
      "Arn":"arn:aws:iam::123456789:group/Developers",
      "CreateDate":"2017-11-01T08:33:22",
      "GroupId":"AGPAI2DADAD3V4XGPRNRCVZYCG",
      "GroupName":"Developers",
      "Path":"/"
   },
   {  
      "Arn":"arn:aws:iam::123456789:group/testgroups/test",
      "CreateDate":"2018-06-04T13:32:34",
      "GroupId":"AGPAJH6IZWADFASD4TDUWDJVPQG",
      "GroupName":"test",
      "Path":"/testgroups/"
   }
]
</pre>
<h3 id="h_68797095715671528637200585">9. List all groups a user is part of</h3>
<hr>
<p>Returns a list of all groups that a specified user is part of in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-list-groups-for-user userName=test</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:ListGroupsForUser</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">userName</td>
<td style="width: 535px;">Name of the user to list groups for</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 63px; width: 740px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 210px;"><strong>Path</strong></td>
<td style="width: 503px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Groups.GroupName</td>
<td style="width: 503px;">Friendly name to identify the group</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Groups.GroupId</td>
<td style="width: 503px;">Stable and unique string identifying the group</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Groups.Arn</td>
<td style="width: 503px;">Amazon Resource Name (ARN) that specifies the group</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Groups.CreateDate</td>
<td style="width: 503px;">Date and time when the group was created</td>
</tr>
<tr>
<td style="width: 210px;">AWS.IAM.Groups.Path</td>
<td style="width: 503px;">Path to the group</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "Arn":"arn:aws:iam::123456789:group/testgroups/test",
      "CreateDate":"2018-06-04T13:32:34",
      "GroupId":"AGPAJH6IZSAFW4TDUWDJVPQG",
      "GroupName":"test",
      "Path":"/testgroups/",
      "UserName":"test"
   }
]
</pre>
<h3 id="h_35662279917581528637214561">10. Add a user to a group</h3>
<hr>
<p>Adds an IAM user to a group in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-add-user-to-group userName=userName34 groupName=test</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:AddUserToGroup</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">userName</td>
<td style="width: 535px;">Name of the user to add to a group</td>
</tr>
<tr>
<td style="width: 179px;">groupName</td>
<td style="width: 535px;">Name of the group to add the user to</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>The user <em>userName34</em> was added to the IAM group: <em>test</em>.
</pre>
<h3 id="h_27602886719481528637231351">11. Create an access key</h3>
<hr>
<p>Creates an access key for an IAM user in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-create-access-key userName=userName34</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:CreateAccessKey</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">userName</td>
<td style="width: 535px;">Name of the user the key is created for</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Path</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Users.AccessKeys.AccessKeyId</td>
<td style="width: 535px;">ID for this access key</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Users.AccessKeys.SecretAccessKey</td>
<td style="width: 535px;">Secret key used to sign requests</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Users.AccessKeys.Status</td>
<td style="width: 535px;">Status of the access key. Active means that the key is valid for API calls, Inactive means it is not valid for API calls.</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Users.AccessKeys.CreateDate</td>
<td style="width: 535px;">Access key creation date</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "AccessKeyId":"AKIASADI6QUYJTFBVHEC5WA",
   "CreateDate":"2018-06-05T06:19:00",
   "SecretAccessKey":"Yj2WWHtipDADADDgZoU7Bvl",
   "Status":"Active",
   "UserName":"userName34"
}
</pre>
<h3 id="h_30007538321371528637244497">12. Update an access key</h3>
<hr>
<p>Changes the status of an access key for an IAM user in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-update-access-key userName=test accessKeyId=AKIAJSFAUQ7EDFPN7Y2D2A status=Inactive</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:UpdateAccessKey</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">userName</td>
<td style="width: 535px;">Name of the user you want to update the access key for</td>
</tr>
<tr>
<td style="width: 179px;">accessKeyId</td>
<td style="width: 535px;">ID of the access key you want to update</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>Access Key with ID AKIAJUQASDAF7E7X5PY2D2A was set to status: Inactive.
</pre>
<h3 id="h_43284584023251528637254677">13. List all access keys for a user</h3>
<hr>
<p>Lists all access keys for an IAM user in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-list-access-keys-for-user userName=userName34</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:ListAccessKeys</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">userName</td>
<td style="width: 535px;">Name of the user you want to list all keys for</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Path</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Users.AccessKeys.AccessKeyId</td>
<td style="width: 535px;">ID for this access key</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Users.AccessKeys.Status</td>
<td style="width: 535px;">Status of the access key. Active means that the key is valid for API calls, Inactive means it is not valid for API calls.</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Users.AccessKeys.CreateDate</td>
<td style="width: 535px;">Access key creation date</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Users.AccessKeys.UserName</td>
<td style="width: 535px;">Name of the IAM user that the key is associated with</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "AccessKeyId":"AKISFX5PN7Y2D2A",
      "CreateDate":"2018-06-05T06:19:44",
      "Status":"Inactive",
      "UserName":"userName34"
   },
   {  
      "AccessKeyId":"AKIAI6SFAQUYJTFBVHEC5WA",
      "CreateDate":"2018-06-05T06:19:00",
      "Status":"Active",
      "UserName":"userName34"
   }
]
</pre>
<h3 id="h_89191343625121528637264663">14. List all policies</h3>
<hr>
<p>Lists all policies, either AWS managed policies or locally managed policies.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-list-policies scope=AWS onlyAttached=True</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:ListPolicies</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Path</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Policies.PolicyName</td>
<td style="width: 535px;">Friendly name identifying the policy (not the ARN)</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Policies.PolicyId</td>
<td style="width: 535px;">Stable and unique string identifying the policy</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Policies.Arn</td>
<td style="width: 535px;">Amazon Resource Name (ARN)</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Policies.Path</td>
<td style="width: 535px;">Path to the policy.</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Policies.DefaultVersionId</td>
<td style="width: 535px;">Identifier for the version of the policy that is set as the default version</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Policies.IsAttachable</td>
<td style="width: 535px;">Specifies whether the policy can be attached to an IAM user, group, or role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Policies.CreateDate</td>
<td style="width: 535px;">Policy creation date</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Policies.UpdateDate</td>
<td style="width: 535px;">Date policy was last updated</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Policies.AttachmentCount</td>
<td style="width: 535px;">Number of entities (users, groups, and roles) that the policy is attached to</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "Arn":"arn:aws:iam::aws:policy/AmazonEC2FullAccess",
      "AttachmentCount":1,
      "CreateDate":"2015-02-06T18:40:15",
      "DefaultVersionId":"v4",
      "IsAttachable":true,
      "Path":"/",
      "PolicyId":"ANPAI3VAJF5ZCRZ7MCQE6",
      "PolicyName":"AmazonEC2FullAccess",
      "UpdateDate":"2018-02-08T18:11:24"
   },
   {  
      "Arn":"arn:aws:iam::aws:policy/AmazonSQSFullAccess",
      "AttachmentCount":1,
      "CreateDate":"2015-02-06T18:41:07",
      "DefaultVersionId":"v1",
      "IsAttachable":true,
      "Path":"/",
      "PolicyId":"ANPAI65L554VRJ33ECQS6",
      "PolicyName":"AmazonSQSFullAccess",
      "UpdateDate":"2015-02-06T18:41:07"
   }
]

</pre>
<h3 id="h_93376955526981528637273805">15. List all roles</h3>
<hr>
<p>Lists all roles in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-list-roles</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:ListRoles</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Path</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Roles.RoleName</td>
<td style="width: 535px;">Friendly name that identifies the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Roles.RoleId</td>
<td style="width: 535px;">Stable and unique string identifying the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Roles.Arn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) specifying the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Roles.CreateDate</td>
<td style="width: 535px;">Date and time the role was created</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Roles.Path</td>
<td style="width: 535px;">Path to the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Roles.AssumeRolePolicyDocument</td>
<td style="width: 535px;">Policy that grants an entity permission to assume the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Roles.Description</td>
<td style="width: 535px;">Description of the role that you provide</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.Roles.MaxSessionDuration</td>
<td style="width: 535px;">The maximum session duration (in seconds) for the specified role. Anyone who uses the AWS CLI or API to assume the role can specify the duration using the optional DurationSeconds API parameter or duration-seconds CLI parameter.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "Arn":"arn:aws:iam::123456789:role/AdminAccess",
      "CreateDate":"2018-05-11T11:27:02",
      "Path":"/",
      "RoleId":"AROAIASM66GZ3IZaDY645EFQ",
      "RoleName":"AdminAccess"
   },
   {  
      "Arn":"arn:aws:iam::123456789:role/service-role/AMI_Info",
      "CreateDate":"2018-04-22T19:14:14",
      "Path":"/service-role/",
      "RoleId":"AROAADIECFBPADNVAAS2ADKTHG4",
      "RoleName":"AMI_Info"
   }
]
</pre>
<h3 id="h_72460316628831528637288904">16. Attach a policy to an entity</h3>
<hr>
<p>Attach a policy to an entity in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-attach-policy type=User entityName=userName34 policyArn=arn:aws:iam::aws:policy/AmazonSQSFullAccess</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Actions: <em>iam:AttachGroupPolicy</em>, <em>iam:AttachRolePolicy</em>, <em>iam:AttachUserPolicy</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">type</td>
<td style="width: 535px;">IAM entity type </td>
</tr>
<tr>
<td style="width: 179px;">entityName</td>
<td style="width: 535px;">Friendly name of the IAM entity to attach the policy to (not the ARN)</td>
</tr>
<tr>
<td style="width: 179px;">policyArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the IAM policy you want to attach</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>Policy was attached to User: <em>userName34</em>
</pre>
<h3 id="h_17675231430671528637303943">17. Detach a policy from an entity</h3>
<hr>
<p>Detaches a policy from an IAM entity in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-detach-policy type=User entityName=userName34 policyArn=arn:aws:iam::aws:policy/AmazonSQSFullAccess</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Actions: <em>iam:DetachGroupPolicy</em>, <em>iam:DetachRolePolicy</em>, <em>iam:DetachUserPolicy</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">type</td>
<td style="width: 535px;">IAM entity type</td>
</tr>
<tr>
<td style="width: 179px;">entityName</td>
<td style="width: 535px;">Friendly name of the IAM entity to detach the policy from (not ARN)</td>
</tr>
<tr>
<td style="width: 179px;">policyArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the policy to detach</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>Policy was detached from User: <em>userName34</em>
</pre>
<h3 id="h_79183429632501528637313930">18. Delete a user's password</h3>
<hr>
<p>Delete the password of an IAM entity in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-delete-login-profile userName=userName34</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:DeleteLoginProfile</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">userName</td>
<td style="width: 535px;">Name of the user you want to delete the password for</td>
</tr>
<tr>
<td style="width: 179px;">policyArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the policy to detach</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>The user <em>userName34</em> login profile has been deleted.
</pre>
<h3 id="h_79642664334321528637357663">19. Delete a group</h3>
<hr>
<p>Delete a group from the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-delete-group groupName=Group123</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:DeleteGroup</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">groupName</td>
<td style="width: 535px;">Name of the IAM group to delete</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>The group <em>Group123</em> has been deleted.
</pre>
<h3 id="h_73326683936131528637368111">20. Remove a user from a group</h3>
<hr>
<p>Remove a user from a group in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-remove-user-from-group userName=userName34  groupName=Group123</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:RemoveUserFromGroup</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">userName</td>
<td style="width: 535px;">Name of the user to remove from a group</td>
</tr>
<tr>
<td style="width: 179px;">groupName</td>
<td style="width: 535px;">Name of the IAM group to update (remove the user from)</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>The user <em>userName34</em> has been removed from group <em>Group123</em>.
</pre>
<h3 id="h_94886199837931528637386867">21. Create a password for a user</h3>
<hr>
<p>Create a password for an IAM user in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-create-login-profile userName=userName34 password=Avd#sdf$12VB6*cvg passwordResetRequired=True</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:CreateLoginProfile</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">userName</td>
<td style="width: 535px;">Name of the user to remove from a group</td>
</tr>
<tr>
<td style="width: 179px;">password</td>
<td style="width: 535px;">New password for the IAM user</td>
</tr>
<tr>
<td style="width: 179px;">passwordResetRequired</td>
<td style="width: 535px;">Specifies whether the user is required to set a new password on next sign in.</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>Login profile was created for user <em>userName34</em>.
</pre>
<h3 id="h_27322833539721528637413111">22. Delete an access key</h3>
<hr>
<p>Create a password for an IAM user in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-delete-access-key userName=userName34 AccessKeyId=AKIAJUAKDJQ7E7X5PADN7Y2D2A</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:DeleteAccessKey</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">userName</td>
<td style="width: 535px;">Name of the user to remove from a group</td>
</tr>
<tr>
<td style="width: 179px;">AccessKeyId</td>
<td style="width: 535px;">Access key ID for the access key to delete</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>The Access Key was deleted.
</pre>
<h3 id="h_22936187241501528637423630">23. Create an instance profile</h3>
<hr>
<p>Creates an instance profile in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-create-instance-profile instanceProfileName=testprofile path=/test/</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:CreateInstanceProfile</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">instanceProfileName</td>
<td style="width: 535px;">Name of the instance profile to create</td>
</tr>
<tr>
<td style="width: 179px;">path</td>
<td style="width: 535px;">Path to the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Path</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Path</td>
<td style="width: 535px;">Path to the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.InstanceProfileName</td>
<td style="width: 535px;">Name identifying the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.InstanceProfileId</td>
<td style="width: 535px;">Stable and unique string identifying the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Arn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) specifying the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.CreateDate</td>
<td style="width: 535px;">Instance profile creation date</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "Arn":"arn:aws:iam::123456789:instance-profile/test/testprofile",
   "CreateDate":"2018-06-05T07:30:15",
   "InstanceProfileId":"/test/",
   "InstanceProfileName":"testprofile",
   "Path":"/test/"
}
</pre>
<h3 id="h_90148501343271528637443566">24. Delete an instance profile</h3>
<hr>
<p>Deletes an instance profile from the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-delete-instance-profile instanceProfileName=testprofile</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:DeleteInstanceProfile</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">instanceProfileName</td>
<td style="width: 535px;">Name of the instance profile to delete</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>The InstanceProfile: testprofile was deleted.</pre>
<h3 id="h_85594047945031528637461268">25. List all instance profiles</h3>
<hr>
<p>Lists all instance profile in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-list-instance-profiles</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:ListInstanceProfiles</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Path</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Path</td>
<td style="width: 535px;">Path to the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.InstanceProfileName</td>
<td style="width: 535px;">Name identifying the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.InstanceProfileId</td>
<td style="width: 535px;">Stable and unique string identifying the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Arn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) specifying the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.CreateDate</td>
<td style="width: 535px;">Instance profile creation date</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Path</td>
<td style="width: 535px;">Path to the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.RoleName</td>
<td style="width: 535px;">Friendly name that identifies the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.RoleId</td>
<td style="width: 535px;">Stable and unique string identifying the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Arn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) specifying the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.CreateDate</td>
<td style="width: 535px;">Role creation date and time</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.AssumeRolePolicyDocument</td>
<td style="width: 535px;">Policy that grants an entity permission to assume the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Description</td>
<td style="width: 535px;">Description of the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.MaxSessionDuration</td>
<td style="width: 535px;">Maximum session duration (in seconds) for the specified role</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "Arn":"arn:aws:iam::123456789:instance-profile/EC2ReadOnly",
      "CreateDate":"2018-05-11T11:27:55",
      "InstanceProfileId":"AIPAAFDFAJ5JLPIFSAFJC6VF6RX5Y",
      "InstanceProfileName":"EC2ReadOnly",
      "Path":"/",
      "RoleArn":"arn:aws:iam::123456789:role/EC2ReadOnly",
      "RoleId":"AR234OAIMZD2SAFWAKKUZK2QMR6",
      "RoleName":"EC2ReadOnly"
   },
   {  
      "Arn":"arn:aws:iam::123456789:instance-profile/SystemsManagerEC2Role",
      "CreateDate":"2018-05-01T14:35:28",
      "InstanceProfileId":"AIPSAFAJN4P5VISFaPFZETEOXOE",
      "InstanceProfileName":"SystemsManagerEC2Role",
      "Path":"/",
      "RoleArn":"arn:aws:iam::123456789:role/SystemsManagerEC2Role",
      "RoleId":"AROAJDLFEISFAZK5MP4DSDFYVE4",
      "RoleName":"SystemsManagerEC2Role"
   }
]

</pre>
<h3 id="h_77573672846781528637536532">26. Add a role to an instance profile</h3>
<hr>
<p>Adds a role to an instance profile in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-add-role-to-instance-profile instanceProfileName=testprofile roleName=EC2ReadOnly</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:AddRoleToInstanceProfile</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">instanceProfileName</td>
<td style="width: 535px;">Name of the instance profile to update</td>
</tr>
<tr>
<td style="width: 179px;">roleName</td>
<td style="width: 535px;">Name of the role to add</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Path</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Path</td>
<td style="width: 535px;">Path to the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.InstanceProfileName</td>
<td style="width: 535px;">Name identifying the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.InstanceProfileId</td>
<td style="width: 535px;">Stable and unique string identifying the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Arn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) specifying the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.CreateDate</td>
<td style="width: 535px;">Instance profile creation date</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Path</td>
<td style="width: 535px;">Path to the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.RoleName</td>
<td style="width: 535px;">Friendly name that identifies the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.RoleId</td>
<td style="width: 535px;">Stable and unique string identifying the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Arn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) specifying the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.CreateDate</td>
<td style="width: 535px;">Role creation date and time</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.AssumeRolePolicyDocument</td>
<td style="width: 535px;">Policy that grants an entity permission to assume the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Description</td>
<td style="width: 535px;">Description of the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.MaxSessionDuration</td>
<td style="width: 535px;">Maximum session duration (in seconds) for the specified role</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>The Role: <em>EC2ReadOnly</em> was added to the Instance Profile: <em>testprofile</em></pre>
<h3 id="h_99899176648521528637548087">27. Remove a role from an instance profile</h3>
<hr>
<p>Adds a role to an instance profile in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-remove-role-from-instance-profile instanceProfileName=testprofile roleName=EC2ReadOnly</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:RemoveRoleFromInstanceProfile</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">instanceProfileName</td>
<td style="width: 535px;">Name of the instance profile to update</td>
</tr>
<tr>
<td style="width: 179px;">roleName</td>
<td style="width: 535px;">Name of the role to remove</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>The Role: <em>EC2ReadOnly</em> was added to the Instance Profile: <em>testprofile</em></pre>
<h3 id="h_65709856051921528637588394">28. List all instance profiles for a role</h3>
<hr>
<p>Lists all instance profile in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-list-instance-profiles-for-role roleName=EC2ReadOnly</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:ListInstanceProfilesForRole</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">roleName</td>
<td style="width: 535px;">Name of the role to list instance profiles for</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Path</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Path</td>
<td style="width: 535px;">Path to the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.InstanceProfileName</td>
<td style="width: 535px;">Name identifying the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.InstanceProfileId</td>
<td style="width: 535px;">Stable and unique string identifying the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Arn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) specifying the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.CreateDate</td>
<td style="width: 535px;">Instance profile creation date</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Path</td>
<td style="width: 535px;">Path to the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.RoleName</td>
<td style="width: 535px;">Friendly name that identifies the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.RoleId</td>
<td style="width: 535px;">Stable and unique string identifying the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Arn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) specifying the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.CreateDate</td>
<td style="width: 535px;">Role creation date and time</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.AssumeRolePolicyDocument</td>
<td style="width: 535px;">Policy that grants an entity permission to assume the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Description</td>
<td style="width: 535px;">Description of the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.MaxSessionDuration</td>
<td style="width: 535px;">Maximum session duration (in seconds) for the specified role</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "Arn":"arn:aws:iam::123456789:instance-profile/EC2ReadOnly",
      "CreateDate":"2018-05-11T11:27:55",
      "InstanceProfileId":"AIPAJAF5JLPIFDSAFJC6VF6RX5Y",
      "InstanceProfileName":"EC2ReadOnly",
      "Path":"/"
   },
   {  
      "Arn":"arn:aws:iam::123456789:instance-profile/test/testprofile",
      "CreateDate":"2018-06-05T07:35:28",
      "InstanceProfileId":"AIPAJRSDFQMQHSDF5CVUZSGMV76",
      "InstanceProfileName":"testprofile",
      "Path":"/test/"
   }
]
</pre>
<h3 id="h_64652386953641528637606870">29. Get instance profile information</h3>
<hr>
<p>Returns profile information for an instance in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-get-instance-profile instanceProfileName=testprofile</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:GetInstanceProfile</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">instanceProfileName</td>
<td style="width: 535px;">Name of the role to list instance profiles for</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Path</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Path</td>
<td style="width: 535px;">Path to the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.InstanceProfileName</td>
<td style="width: 535px;">Name identifying the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.InstanceProfileId</td>
<td style="width: 535px;">Stable and unique string identifying the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Arn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) specifying the instance profile</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.CreateDate</td>
<td style="width: 535px;">Instance profile creation date</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Path</td>
<td style="width: 535px;">Path to the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.RoleName</td>
<td style="width: 535px;">Friendly name that identifies the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.RoleId</td>
<td style="width: 535px;">Stable and unique string identifying the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Arn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) specifying the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.CreateDate</td>
<td style="width: 535px;">Role creation date and time</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.AssumeRolePolicyDocument</td>
<td style="width: 535px;">Policy that grants an entity permission to assume the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Description</td>
<td style="width: 535px;">Description of the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.MaxSessionDuration</td>
<td style="width: 535px;">Maximum session duration (in seconds) for the specified role</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "Arn":"arn:aws:iam::123456789:instance-profile/test/testprofile",
   "CreateDate":"2018-06-05T07:35:28",
   "InstanceProfileId":"AIPAJRASDFQMQH5ASFCVUZSGMV76",
   "InstanceProfileName":"testprofile",
   "Path":"/test/",
   "RoleArn":"arn:aws:iam::123456789:role/EC2ReadOnly",
   "RoleId":"AROAASFIMZD2WAKSAFKUZK2QMR6",
   "RoleName":"EC2ReadOnly"
}
</pre>
<h3 id="h_90184122455351528637618510">30. Get role information</h3>
<hr>
<p>Returns information for a role in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-get-role roleName=ec2readonly</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:GetRole</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">roleName</td>
<td style="width: 535px;">Name of the role to return information for</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Path</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Path</td>
<td style="width: 535px;">Path to the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.RoleName</td>
<td style="width: 535px;">Friendly name that identifies the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.RoleId</td>
<td style="width: 535px;">Stable and unique string identifying the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Arn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) specifying the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.CreateDate</td>
<td style="width: 535px;">Role creation date and time</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.AssumeRolePolicyDocument</td>
<td style="width: 535px;">Policy that grants an entity permission to assume the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Description</td>
<td style="width: 535px;">Description of the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.MaxSessionDuration</td>
<td style="width: 535px;">Maximum session duration (in seconds) for the specified role</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "Arn":"arn:aws:iam::123456789:role/EC2ReadOnly",
   "CreateDate":"2018-05-11T11:27:55",
   "Path":"/",
   "RoleId":"AROAISAFMZD2WAKKUSFZK2QMR6",
   "RoleName":"EC2ReadOnly"
}
</pre>
<h3 id="h_70526274457051528637627532">31. Delete a role</h3>
<hr>
<p>Returns information for a role in the Amazon IAM system.</p>
<h5>Command Example</h5>
<p><code>!aws-iam-delete-role roleName=test-role</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:DeleteRole</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">roleName</td>
<td style="width: 535px;">Name of the role to delete</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Raw Output</h5>
<pre>The Role: <em>test-role</em> was deleted.
</pre>
<h3 id="h_74037147358741528637636496">32. Create a role</h3>
<hr>
<p>Create a role in the Amazon IAM system.</p>
<h5>Command Example</h5>
<pre><code>!aws-iam-create-role roleName=testrole assumeRolePolicyDocument="{
"Version": "2012-10-17",
"Statement": [
{
"Effect": "Allow",
"Principal": {
"Service": "ec2.amazonaws.com"
},
"Action": "sts:AssumeRole"
}
]
}" description="a test role"</code></pre>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>iam:CreateRole</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">roleName</td>
<td style="width: 535px;">Name of the role to create</td>
</tr>
<tr>
<td style="width: 179px;">assumeRolePolicyDocumentName</td>
<td style="width: 535px;">Trust relationship policy document that grants an entity permission to assume the role </td>
</tr>
<tr>
<td style="width: 179px;">path</td>
<td style="width: 535px;">Path to the role</td>
</tr>
<tr>
<td style="width: 179px;">description</td>
<td style="width: 535px;">Description of the role</td>
</tr>
<tr>
<td style="width: 179px;">maxSessionDuration</td>
<td style="width: 535px;">The maximum session duration (in hours) that you want to set for the specified role. If you do not specify a value for this setting, the default maximum is one hour. Valid parameter values: 1 hour to 12 hours.</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) of the role to assume</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">Identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">Duration of the role session, in seconds (the value can range from 900 seconds to the maximum session duration set for the role)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Path</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Path</td>
<td style="width: 535px;">Path to the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.RoleName</td>
<td style="width: 535px;">Friendly name that identifies the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.RoleId</td>
<td style="width: 535px;">Stable and unique string identifying the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Arn</td>
<td style="width: 535px;">Amazon Resource Name (ARN) specifying the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.CreateDate</td>
<td style="width: 535px;">Role creation date and time</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.AssumeRolePolicyDocument</td>
<td style="width: 535px;">Policy that grants an entity permission to assume the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.Description</td>
<td style="width: 535px;">Description of the role</td>
</tr>
<tr>
<td style="width: 179px;">AWS.IAM.InstanceProfiles.Roles.MaxSessionDuration</td>
<td style="width: 535px;">Maximum session duration (in seconds) for the specified role</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "Arn":"arn:aws:iam::123456789:role/test-role",
   "Path":"/",
   "RoleId":"ARsdOAJGHGQNWTADXZ2TT3DKY",
   "RoleName":"test-role"
}
</pre>
<p> </p>
<h3 id="h_6231318754001544460248411">33. Create a policy</h3>
<hr>
<p>Creates a new managed policy for your AWS account. This operation creates a policy version with a version identifier of v1 and sets v1 as the policy's default version.</p>
<h5>Base Command</h5>
<p><code>aws-iam-create-policy</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 145px;"><strong>Argument Name</strong></th>
<th style="width: 492px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 145px;">policyName</td>
<td style="width: 492px;">The friendly name of the policy.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145px;">policyDocument</td>
<td style="width: 492px;">The JSON policy document that you want to use as the content for the new policy.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 145px;">path</td>
<td style="width: 492px;">The path for the policy.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 145px;">description</td>
<td style="width: 492px;">A friendly description of the policy.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 145px;">roleArn</td>
<td style="width: 492px;">The Amazon Resource Name (ARN) of the role to assume.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 145px;">roleSessionName</td>
<td style="width: 492px;">An identifier for the assumed role session.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 145px;">roleSessionDuration</td>
<td style="width: 492px;">The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 354px;"><strong>Path</strong></th>
<th style="width: 63px;"><strong>Type</strong></th>
<th style="width: 291px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 354px;">AWS.IAM.Policies.PolicyName</td>
<td style="width: 63px;">string</td>
<td style="width: 291px;">The friendly name (not ARN) identifying the policy.</td>
</tr>
<tr>
<td style="width: 354px;">AWS.IAM.Policies.PolicyId</td>
<td style="width: 63px;">string</td>
<td style="width: 291px;">The stable and unique string identifying the policy.</td>
</tr>
<tr>
<td style="width: 354px;">AWS.IAM.Policies.Arn</td>
<td style="width: 63px;">string</td>
<td style="width: 291px;">The Amazon Resource Name (ARN). ARNs are unique identifiers for AWS resources.</td>
</tr>
<tr>
<td style="width: 354px;">AWS.IAM.Policies.Path</td>
<td style="width: 63px;">string</td>
<td style="width: 291px;">The path to the policy.</td>
</tr>
<tr>
<td style="width: 354px;">AWS.IAM.Policies.DefaultVersionId</td>
<td style="width: 63px;">string</td>
<td style="width: 291px;">The identifier for the version of the policy that is set as the default version.</td>
</tr>
<tr>
<td style="width: 354px;">AWS.IAM.Policies.AttachmentCount</td>
<td style="width: 63px;">number</td>
<td style="width: 291px;">The number of entities (users, groups, and roles) that the policy is attached to.</td>
</tr>
<tr>
<td style="width: 354px;">AWS.IAM.Policies.PermissionsBoundaryUsageCount</td>
<td style="width: 63px;">number</td>
<td style="width: 291px;">The number of entities (users and roles) for which the policy is used to set the permissions boundary.</td>
</tr>
<tr>
<td style="width: 354px;">AWS.IAM.Policies.IsAttachable</td>
<td style="width: 63px;">boolean</td>
<td style="width: 291px;">Specifies whether the policy can be attached to an IAM user, group, or role.</td>
</tr>
<tr>
<td style="width: 354px;">AWS.IAM.Policies.Description</td>
<td style="width: 63px;">string</td>
<td style="width: 291px;">A friendly description of the policy.</td>
</tr>
<tr>
<td style="width: 354px;">AWS.IAM.Policies.CreateDate</td>
<td style="width: 63px;">date</td>
<td style="width: 291px;">Date and time the policy was created, in ISO 8601 date-time format</td>
</tr>
<tr>
<td style="width: 354px;">AWS.IAM.Policies.UpdateDate</td>
<td style="width: 63px;">date</td>
<td style="width: 291px;">Date and time the policy was updated, in ISO 8601 date-time format</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!aws-iam-create-policy policyName=test-policy policyDocument="{<br>"Version": "2012-10-17",<br>"Statement": [<br>{<br>"Sid": "VisualEditor0",<br>"Effect": "Allow",<br>"Action": "guardduty:CreateIPSet",<br>"Resource": "arn:aws:guardduty:<em>:</em>:detector/<em>"<br>},<br>{<br>"Sid": "VisualEditor1",<br>"Effect": "Allow",<br>"Action": "guardduty:CreateDetector",<br>"Resource": "</em>"<br>}<br>]<br>}"</pre>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/49724512-20b4ef00-fc72-11e8-9cd9-e047e2cf2307.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/49724512-20b4ef00-fc72-11e8-9cd9-e047e2cf2307.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/49724447-f5ca9b00-fc71-11e8-88ac-301540e59c07.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/49724447-f5ca9b00-fc71-11e8-88ac-301540e59c07.png" alt="image"></a></p>
<h3 id="h_3523892546431544460254180">34. Delete a policy</h3>
<hr>
<p>Deletes the specified managed policy. Before you can delete a managed policy, you must first detach the policy from all users, groups, and roles that it is attached to. In addition you must delete all the policy's versions.</p>
<h5>Base Command</h5>
<p><code>aws-iam-delete-policy</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 138px;"><strong>Argument Name</strong></th>
<th style="width: 499px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138px;">policyArn</td>
<td style="width: 499px;">The Amazon Resource Name (ARN) of the IAM policy you want to delete.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 138px;">roleArn</td>
<td style="width: 499px;">The Amazon Resource Name (ARN) of the role to assume.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">roleSessionName</td>
<td style="width: 499px;">An identifier for the assumed role session.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">roleSessionDuration</td>
<td style="width: 499px;">The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!aws-iam-delete-policy policyArn=arn:aws:iam::123456789:policy/test-policy</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/49729546-78595780-fc7e-11e8-843e-a514b796ace9.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/49729546-78595780-fc7e-11e8-843e-a514b796ace9.png" alt="image"></a></p>
<h3 id="h_5115172778831544460258719">35. Create a new version of a policy</h3>
<hr>
<p>Creates a new version of the specified managed policy. To update a managed policy, you create a new policy version. A managed policy can have up to five versions. If the policy has five versions, you must delete an existing version using DeletePolicyVersion before you create a new version. Optionally, you can set the new version as the policy's default version. The default version is the version that is in effect for the IAM users, groups, and roles to which the policy is attached.</p>
<h5>Base Command</h5>
<p><code>aws-iam-create-policy-version</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 136px;"><strong>Argument Name</strong></th>
<th style="width: 501px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 136px;">policyArn</td>
<td style="width: 501px;">The Amazon Resource Name (ARN) of the IAM policy to which you want to add a new version.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">policyDocument</td>
<td style="width: 501px;">The JSON policy document that you want to use as the content for this new version of the policy.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">setAsDefault</td>
<td style="width: 501px;">Specifies whether to set this version as the policy's default version.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">roleArn</td>
<td style="width: 501px;">The Amazon Resource Name (ARN) of the role to assume.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">roleSessionName</td>
<td style="width: 501px;">An identifier for the assumed role session.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">roleSessionDuration</td>
<td style="width: 501px;">The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 298px;"><strong>Path</strong></th>
<th style="width: 49px;"><strong>Type</strong></th>
<th style="width: 361px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 298px;">AWS.IAM.Policies.Versions.Document</td>
<td style="width: 49px;">string</td>
<td style="width: 361px;">The policy document.</td>
</tr>
<tr>
<td style="width: 298px;">AWS.IAM.Policies.Versions.VersionId</td>
<td style="width: 49px;">string</td>
<td style="width: 361px;">The identifier for the policy version.</td>
</tr>
<tr>
<td style="width: 298px;">AWS.IAM.Policies.Versions.IsDefaultVersion</td>
<td style="width: 49px;">string</td>
<td style="width: 361px;">The identifier for the policy version.</td>
</tr>
<tr>
<td style="width: 298px;">AWS.IAM.Policies.Versions.CreateDate</td>
<td style="width: 49px;">string</td>
<td style="width: 361px;">Date and time the policy version was created, in ISO 8601 date-time format</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!aws-iam-create-policy-version policyArn=arn:aws:iam::123456789:policy/test-policy policyDocument="{<br>"Version": "2012-10-17",<br>"Statement": [<br>{<br>"Sid": "VisualEditor0",<br>"Effect": "Allow",<br>"Action": "guardduty:CreateIPSet",<br>"Resource": "arn:aws:guardduty:<em>:</em>:detector/<em>"<br>},<br>{<br>"Sid": "VisualEditor1",<br>"Effect": "Allow",<br>"Action": "guardduty:CreateDetector",<br>"Resource": "</em>"<br>}<br>]<br>}" setAsDefault=True</pre>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/49732510-9d05fd00-fc87-11e8-9c5d-c8e7c77b85f2.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/49732510-9d05fd00-fc87-11e8-9c5d-c8e7c77b85f2.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/49732480-86f83c80-fc87-11e8-9ddd-969d03c4aa0d.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/49732480-86f83c80-fc87-11e8-9ddd-969d03c4aa0d.png" alt="image"></a></p>
<h3 id="h_83948698411241544460263116">36.  Delete a policy version</h3>
<hr>
<p>Deletes the specified version from the specified managed policy. You cannot delete the default version from a policy using this API. To delete the default version from a policy, use DeletePolicy . To find out which version of a policy is marked as the default version, use ListPolicyVersions .</p>
<h5>Base Command</h5>
<p><code>aws-iam-delete-policy-version</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 136px;"><strong>Argument Name</strong></th>
<th style="width: 501px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 136px;">policyArn</td>
<td style="width: 501px;">The Amazon Resource Name (ARN) of the IAM policy from which you want to delete a version.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">versionId</td>
<td style="width: 501px;">The policy version to delete.</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 136px;">roleArn</td>
<td style="width: 501px;">The Amazon Resource Name (ARN) of the role to assume.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">roleSessionName</td>
<td style="width: 501px;">An identifier for the assumed role session.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 136px;">roleSessionDuration</td>
<td style="width: 501px;">The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!aws-iam-delete-policy-version policyArn=arn:aws:iam::123456789:policy/test-policy versionId=v1</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/49732629-f2daa500-fc87-11e8-90ab-36d52d64446c.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/49732629-f2daa500-fc87-11e8-90ab-36d52d64446c.png" alt="image"></a></p>
<h3 id="h_30437568018241544460273321">37. Get information for all versions of a policy</h3>
<hr>
<p>Lists information about the versions of the specified managed policy, including the version that is currently set as the policy's default version.</p>
<h5>Base Command</h5>
<p><code>aws-iam-list-policy-versions</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 137px;"><strong>Argument Name</strong></th>
<th style="width: 500px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 137px;">policyArn</td>
<td style="width: 500px;">The Amazon Resource Name (ARN) of the IAM policy for which you want the versions.</td>
<td style="width: 71px;">Required</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 301px;"><strong>Path</strong></th>
<th style="width: 61px;"><strong>Type</strong></th>
<th style="width: 346px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 301px;">AWS.IAM.Policies.Versions.Document</td>
<td style="width: 61px;">string</td>
<td style="width: 346px;">The policy document</td>
</tr>
<tr>
<td style="width: 301px;">AWS.IAM.Policies.Versions.VersionId</td>
<td style="width: 61px;">string</td>
<td style="width: 346px;">The identifier for the policy version</td>
</tr>
<tr>
<td style="width: 301px;">AWS.IAM.Policies.Versions.IsDefaultVersion</td>
<td style="width: 61px;">boolean</td>
<td style="width: 346px;">Specifies whether the policy version is set as the policy's default version</td>
</tr>
<tr>
<td style="width: 301px;">AWS.IAM.Policies.Versions.CreateDate</td>
<td style="width: 61px;">date</td>
<td style="width: 346px;">Date and time the policy version was created, in ISO 8601 date-time format</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!aws-iam-list-policy-versions policyArn=arn:aws:iam::123456789:policy/test-policy</pre>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/49733676-cc6a3900-fc8a-11e8-89b4-446e6a37a2b4.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/49733676-cc6a3900-fc8a-11e8-89b4-446e6a37a2b4.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/49732889-af346b00-fc88-11e8-98ff-7ad3160a3082.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/49732889-af346b00-fc88-11e8-98ff-7ad3160a3082.png" alt="image"></a></p>
<h3 id="h_16892468322931544460281747">38. Get information for a policy version</h3>
<hr>
<p>Retrieves information about the specified version of the specified managed policy, including the policy document.</p>
<h5>Base Command</h5>
<p><code>aws-iam-get-policy-version</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 138px;"><strong>Argument Name</strong></th>
<th style="width: 499px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 138px;">policyArn</td>
<td style="width: 499px;">The Amazon Resource Name (ARN) of the managed policy that you want information about</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 138px;">versionId</td>
<td style="width: 499px;">Identifies the policy version to retrieve</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 138px;">roleArn</td>
<td style="width: 499px;">The Amazon Resource Name (ARN) of the role to assume.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">roleSessionName</td>
<td style="width: 499px;">An identifier for the assumed role session</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 138px;">roleSessionDuration</td>
<td style="width: 499px;">The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 300px;"><strong>Path</strong></th>
<th style="width: 421px;"><strong>Description</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 300px;">AWS.IAM.Policies.Versions.Document</td>
<td style="width: 421px;">The policy document</td>
</tr>
<tr>
<td style="width: 300px;">AWS.IAM.Policies.Versions.VersionId</td>
<td style="width: 421px;">The identifier for the policy version</td>
</tr>
<tr>
<td style="width: 300px;">AWS.IAM.Policies.Versions.IsDefaultVersion</td>
<td style="width: 421px;">Specifies whether the policy version is set as the policy's default version</td>
</tr>
<tr>
<td style="width: 300px;">AWS.IAM.Policies.Versions.CreateDate</td>
<td style="width: 421px;">Date and time the policy version was created, in ISO 8601 date-time format</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Command Example</h5>
<pre>!aws-iam-get-policy-version policyArn=arn:aws:iam::123456789:policy/test-policy versionId=v3</pre>
<h5>Context Example</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/49733777-1521f200-fc8b-11e8-9aa8-7439bea2bc6e.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/49733777-1521f200-fc8b-11e8-9aa8-7439bea2bc6e.png" alt="image"></a></p>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/49733822-3551b100-fc8b-11e8-85bf-e63f210c7ce0.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/49733822-3551b100-fc8b-11e8-85bf-e63f210c7ce0.png" alt="image"></a></p>
<h3 id="h_87933834125311544460287721">39. Set a default (operative) policy version</h3>
<hr>
<p>Sets the specified version of the specified policy as the policy's default (operative) version. This operation affects all users, groups, and roles that the policy is attached to.</p>
<h5>Base Command</h5>
<p><code>aws-iam-set-default-policy-version</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 133px;"><strong>Argument Name</strong></th>
<th style="width: 504px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 133px;">policyArn</td>
<td style="width: 504px;">The Amazon Resource Name (ARN) of the IAM policy whose default version you want to set</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 133px;">versionId</td>
<td style="width: 504px;">The version of the policy to set as the default (operative) version</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 133px;">roleArn</td>
<td style="width: 504px;">The Amazon Resource Name (ARN) of the role to assume</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">roleSessionName</td>
<td style="width: 504px;">An identifier for the assumed role session</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">roleSessionDuration</td>
<td style="width: 504px;">The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!aws-iam-set-default-policy-version policyArn=arn:aws:iam::123456789:policy/test-policy versionId=v2</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/49733914-7649c580-fc8b-11e8-976d-e9008404b136.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/49733914-7649c580-fc8b-11e8-976d-e9008404b136.png" alt="image"></a></p>
<h3 id="h_34904695527661544460299590">40. Create an account alias</h3>
<hr>
<p>Creates an alias for your AWS account.</p>
<h5>Base Command</h5>
<p><code>aws-iam-create-account-alias</code></p>
<h5>Input</h5>
<table style="width: 746px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 133px;"><strong>Argument Name</strong></th>
<th style="width: 504px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 133px;">accountAlias</td>
<td style="width: 504px;">The account alias to create</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 133px;">roleArn</td>
<td style="width: 504px;">The Amazon Resource Name (ARN) of the role to assume</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">roleSessionName</td>
<td style="width: 504px;">An identifier for the assumed role session</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 133px;">roleSessionDuration</td>
<td style="width: 504px;">The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!aws-iam-create-account-alias accountAlias=test-alias</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/49734027-b4df8000-fc8b-11e8-87bf-770474d39477.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/49734027-b4df8000-fc8b-11e8-87bf-770474d39477.png" alt="image"></a></p>
<h3 id="h_41">41. Delete an account alias</h3>
<hr>
<p>Deletes the specified AWS account alias.</p>
<h5>Base Command</h5>
<p><code>aws-iam-delete-account-alias</code></p>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 137px;"><strong>Argument Name</strong></th>
<th style="width: 500px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 137px;">accountAlias</td>
<td style="width: 500px;">The name of the account alias to delete</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 137px;">roleArn</td>
<td style="width: 500px;">The Amazon Resource Name (ARN) of the role to assume</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">roleSessionName</td>
<td style="width: 500px;">An identifier for the assumed role session</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 137px;">roleSessionDuration</td>
<td style="width: 500px;">The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!aws-iam-delete-account-alias accountAlias=demisto-test-alias</pre>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/34302832/49734082-d50f3f00-fc8b-11e8-8306-96924dbda242.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/34302832/49734082-d50f3f00-fc8b-11e8-8306-96924dbda242.png" alt="image"></a></p>
<hr>