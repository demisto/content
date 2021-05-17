<!-- HTML_DOC -->
<p>Use this integration to detect and manage threats to your AWS system.</p>
<p>We recommend that you use roles that have the following bulit-in AWS policies:</p>
<ul>
<li><em>AmazonGuardDutyFullAccess</em></li>
<li><em>AmazonGuardDutyReadOnlyAccess</em></li>
</ul>
<h2>Prerequisites</h2>
<p>It is important that you familiarize yourself with and complete all steps detailed in the <a href="https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication">Amazon AWS Integrations Configuration Guide</a>.</p>
<h2>Configure the AWS GuardDuty Integration on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for AWS - GuardDuty.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>
<strong>Name</strong>: a textual name for the integration instance</li>
<li><strong>AWS Default Region</strong></li>
<li><strong>Role Arn</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Incident type</strong></li>
<li>
<strong>GuardDuty Severity Level </strong>(Low, Medium, High)</li>
<li><strong>Role Session Name</strong></li>
<li><strong>Role Session Duration</strong></li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and token.</li>
</ol>
<h2>Fetched Incidents Data</h2>
<ul>
<li>The integration fetches newly created Guard DutyFindings. Findings that are fetched are moved to Guard duty archive. Each integration instance can fetch findings from a single AWS Region.</li>
<li>Each region can have a maximum of 1,000 member accounts that are linked to a guard duty master account. For more information see the <a href="https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_accounts.html">Amazon GuardDuty documentation</a>. </li>
<li>You can set the severity level of the findings to be fetched. "Low", "Medium", "High".<br>For example, if you set the severity level to "Medium", the integration will only fetch findings with severity level of Medium and higher.</li>
<li>Findings in archived status will not be retrieved.</li>
<li>The initial fetch interval is one minute.</li>
</ul>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_82264373541528784028440">Create an Amazon GuardDuty detector: aws-gd-create-detector</a></li>
<li><a href="#h_892625478181528784240221">Delete an Amazon GuardDuty detector: aws-gd-delete-detector</a></li>
<li><a href="#h_416159697371528784783294">Retrieve an Amazon GuardDuty detector: aws-gd-get-detector</a></li>
<li><a href="#h_889083693611528785627734">Update an Amazon GuardDuty detector: aws-gd-update-detector</a></li>
<li><a href="#h_98618764901528786209201">Create an IP whitelist: aws-gd-create-ip-set</a></li>
<li><a href="#h_6842055291241528787100478">Delete an IP whitelist: aws-gd-delete-ip-set</a></li>
<li><a href="#h_8181148091631528787990457">List all Amazon GuardDuty detectors: aws-gd-list-detectors</a></li>
<li><a href="#h_7102054062071528790260514">Update an IP whitelist: aws-gd-update-ip-set</a></li>
<li><a href="#h_1460092422561528791753725">Get IP whitelist information: aws-gd-get-ip-set</a></li>
<li><a href="#h_5415256283101528792091331">List all IP whitelists: aws-gd-list-ip-sets</a></li>
<li><a href="#h_5495194414281528792590484">Create a threat intelligence set: aws-gd-create-threatintel-set</a></li>
<li><a href="#h_420964804921528793220608">Delete a threat intelligence set: aws-gd-delete-threatintel-set</a></li>
<li><a href="#h_5402018005611528793742779">Get threat intelligence set information: aws-gd-threatintel-set</a></li>
<li><a href="#h_121885886351528794056209">List all threat intelligence sets: aws-gd-list-threatintel-sets</a></li>
<li><a href="#h_67638147141528795046616">Update a threat intelligence set: aws-gd-update-threatintel-set</a></li>
<li><a href="#h_151918107981528795343851">List Amazon GuardDuty findings for a specific detector: aws-gd-list-findings</a></li>
<li><a href="#h_939116898871528795749854">Describe Amazon GuardDuty findings for a specific detector: aws-gd-get-findings</a></li>
<li><a href="#h_5612231099811528796201611">Generate example findings: aws-gd-create-sample-findings</a></li>
<li><a href="#h_7397716710801528796473289">Archive Amazon GuardDuty findings: aws-gd-archive-findings</a></li>
<li><a href="#h_90473052511841528796654452">Un-archive Amazon GuardDuty findings: aws-gd-unarchive-findings</a></li>
<li><a href="#h_65342598912931528796902361">Mark Amazon GuardDuty findings as useful or not useful: aws-gd-update-findings-feedback</a></li>
</ol>
<hr>
<h3 id="h_82264373541528784028440">Create an Amazon GuardDuty detector: aws-gd-create-detector</h3>
<p>Creates an Amazon GuardDuty detector on the AWS account specified in the integration instance.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-create-detector enabled=True region=eu-west-2</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:CreateDetector</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">enabled</td>
<td style="width: 535px;">A boolean value that specifies whether to enable the detector</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<td style="width: 210px;">AWS.GuardDuty.Detectors.DetectorId</td>
<td style="width: 503px;">Unique ID of the created detector</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "DetectorId":"38b1235ed3fe245279cd0c8e235db0715ac5561eb"
}
</pre>
<hr>
<h3 id="h_892625478181528784240221">Delete an Amazon GuardDuty detector: aws-gd-delete-detector</h3>
<p>Deletes an Amazon GuardDuty detector on the AWS account specified in the integration instance.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-delete-detector detectorId=38b1235ed3fe245279cd0c8e235db0715ac5561eb</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:DeleteDetector</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">enabled</td>
<td style="width: 535px;">A boolean value that specifies whether to enable the detector</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<pre>The Detector <em>38b1235ed3fe245279cd0c8e235db0715ac5561eb</em> has been deleted.
</pre>
<hr>
<h3 id="h_416159697371528784783294">Retrieve an Amazon GuardDuty detector: aws-gd-get-detector</h3>
<p>Retrives an Amazon GuardDuty detector by detectorId.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-get-detector detectorId=38b1ed3fe279fdascd0c8edb071dsf5ac5561eb region=eu-west-2</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:GetDetector</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">Unique ID of the detector that you want to retrieve</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<td style="width: 210px;">AWS.GuardDuty.Detectors.DetectorId</td>
<td style="width: 503px;">Unique ID of the created detector</td>
</tr>
<tr>
<td style="width: 210px;">AWS.GuardDuty.Detectors.CreatedAt</td>
<td style="width: 503px;">The first time a resource was created</td>
</tr>
<tr>
<td style="width: 210px;">AWS.GuardDuty.Detectors.ServiceRole</td>
<td style="width: 503px;">Customer serviceRole name or ARN for accessing customer resources</td>
</tr>
<tr>
<td style="width: 210px;">AWS.GuardDuty.Detectors.Status</td>
<td style="width: 503px;">Status of the detector</td>
</tr>
<tr>
<td style="width: 210px;">AWS.GuardDuty.Detectors.UpdatedAt</td>
<td style="width: 503px;">The time a resource was last updated</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{ 
   "CreatedAt":"2018-06-07T13:46:37.031Z",
   "DetectorId":"38b1ed3fe279cd0c8edb0715ac5561eb",
   "ServiceRole":"arn:aws:iam::123456789:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
   "Status":"DISABLED",
   "UpdatedAt":"2018-06-07T13:46:37.031Z"
}
</pre>
<hr>
<h3 id="h_889083693611528785627734">Update an Amazon GuardDuty detector: aws-gd-update-detector</h3>
<p>Updates an Amazon GuardDuty detector by detectorId.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-get-detector detectorId=38b1ed3fe279fdascd0c8edb071dsf5ac5561eb enable=True</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:UpdateDetector</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">Unique ID of the detector that you want to retrieve</td>
</tr>
<tr>
<td style="width: 179px;">enable</td>
<td style="width: 535px;">Updated boolean value for the detector that specifies whether the detector is enabled</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<pre>The Detector <em>38b1ed3fe279fdascd0c8edb071dsf5ac5561eb</em> was updated.</pre>
<hr>
<h3 id="h_98618764901528786209201">Create an IP white list: aws-gd-create-ip-set</h3>
<p>Creates a list of trusted IP addresses (IPSet) that were white listed for secure communication with AWS insfrastructure and applications.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-create-ip-set format=TXT location=https://s3.eu-central-1.amazonaws.com/test/ipset.txt activate=True detectorId=38b1ed3fe279czvasdd0c8edb0715azdsfc5561eb name=test region=eu-west-2</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:CreateIPSet</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">activate</td>
<td style="width: 535px;">A boolean value that indicates whether GuardDuty uses<br>the uploaded IPSet</td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">Unique ID of the detector that you want to update</td>
</tr>
<tr>
<td style="width: 179px;">format</td>
<td style="width: 535px;">Format of the file that contains the IPSet.</td>
</tr>
<tr>
<td style="width: 179px;">location</td>
<td style="width: 535px;">URI of the file that contains the IPSet, for example, https://s3.us-west-2.amazonaws.com/my-bucket/my-object-key</td>
</tr>
<tr>
<td style="width: 179px;">name</td>
<td style="width: 535px;">Friendly name for the IPSet, which displays in all findings that are triggered by activities that involve IP addresses included in this IPSet</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<td style="width: 210px;">AWS.GuardDuty.IPSet.IpSetId</td>
<td style="width: 503px;">A list of trusted IP addresses that have been whitelisted for secure communication with AWS infrastructure and applications</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "DetectorId":"38b1ed3fe279czvasdd0c8edb0715azdsfc5561eb",
   "IpSetId":"7eb1f440be5931f168280b574a26d44d"
}</pre>
<hr>
<h3 id="h_6842055291241528787100478">Delete an IP whitelist: aws-gd-delete-ip-set</h3>
<p>Deletes the IPSet specified by IPSet ID.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-delete-ip-set detectorId=38b1ed3fe279cd0c8edb0715ac5561eb ipSetId=7eb1f440be5931f168280b574a26d44d region=eu-west-2</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:DeleteIPSet</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">Unique ID of the detector that you want to update</td>
</tr>
<tr>
<td style="width: 179px;">ipSetId</td>
<td style="width: 535px;">Unique ID of the IPSet to delete</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<pre>The IPSet <em>7eb1f440be593asd1f168280b57asd4a26d44d</em> has been deleted from Detector <em>38b1ed3fe279cdasd0c8edb0715ac5561eb</em>.</pre>
<hr>
<h3 id="h_8181148091631528787990457">List all Amazon GuardDuty detectors: aws-gd-list-detectors</h3>
<p>Lists all Amazon GuardDuty detectors.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-list-detectors region=eu-west-2</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:ListDetectors</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<td style="width: 210px;">AWS.GuardDuty.Detectors.detectorId</td>
<td style="width: 503px;">Unique ID of the detector</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "DetectorId":"38b1ed3fe279czvasdd0c8edb0715azdsfc5561eb"
}</pre>
<hr>
<h3 id="h_7102054062071528790260514">Update an IP whitelist: aws-gd-update-ip-set</h3>
<p>Updates the IPSet specified by the IPSet ID.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-update-ip-set detectorId=38b1ed3fe279cd0c8edb0715ac5561eb ipSetId=7eb1f440be5931f168280b574a26d44d activate=False region=eu-west-2</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:UpdateIPSet</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">activate</td>
<td style="width: 535px;">A boolean value that indicates whether GuardDuty uses<br>the uploaded IPSet</td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">Unique ID of the detector that you want to update</td>
</tr>
<tr>
<td style="width: 179px;">ipSetId</td>
<td style="width: 535px;">Unique ID that specifies the IPSet that you want to update</td>
</tr>
<tr>
<td style="width: 179px;">location</td>
<td style="width: 535px;">URI of the file that contains the IPSet, for example, https://s3.us-west-2.amazonaws.com/my-bucket/my-object-key</td>
</tr>
<tr>
<td style="width: 179px;">name</td>
<td style="width: 535px;">Friendly name for the IPSet, which displays in all findings that are triggered by activities that involve IP addresses included in this IPSet</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<pre>The IPSet <em>{0}</em> was been updated.</pre>
<hr>
<h3 id="h_1460092422561528791753725">Get IP whitelist information: aws-gd-get-ip-set</h3>
<p>Retrives information for an IPSet.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-get-ip-set detectorId=38b1ed3fesdf279cd0c8edbdsf071sdgfac5561eb ipSetId=7eb1sdff440be5931f1682adf80b574a26d44d region=eu-west-2</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:GetIPSet</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">The detectorID that specifies the GuardDuty service whose IPSet you want to retrieve</td>
</tr>
<tr>
<td style="width: 179px;">ipSetId</td>
<td style="width: 535px;">Unique ID that specifies the IPSet that you want to describe</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<td style="width: 210px;">AWS.GuardDuty.Detectors.IPSet.IpSetId</td>
<td style="width: 503px;">Unique ID for the IPSet</td>
</tr>
<tr>
<td style="width: 210px;">AWS.GuardDuty.Detectors.IPSet.Format</td>
<td style="width: 503px;">Format of the file that contains the IPSet</td>
</tr>
<tr>
<td style="width: 210px;">AWS.GuardDuty.Detectors.IPSet.Location</td>
<td style="width: 503px;">URI of the file that contains the IPSet</td>
</tr>
<tr>
<td style="width: 210px;">AWS.GuardDuty.Detectors.IPSet.Name</td>
<td style="width: 503px;">Friendly name to identify the IPSet</td>
</tr>
<tr>
<td style="width: 210px;">AWS.GuardDuty.Detectors.IPSet.Status</td>
<td style="width: 503px;">Status of the uploaded IPSet file</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "DetectorId":"38b1edsfd3fe279cd0dsfc8edb07sdf15asdfc5561eb",
   "Format":"TXT",
   "IpSetId":"7eb1f440sdfafbe5931f168280dsfb574a26d44d",
   "Location":"https://s3.eu-central-1.amazonaws.com/test/ipset.txt",
   "Name":"test",
   "Status":"DELETED"
}
</pre>
<hr>
<h3 id="h_5415256283101528792091331">List all IP whitelists: aws-gd-list-ip-sets</h3>
<p>Lists all IPSets in GuardDuty.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-list-ip-sets detectorId=38b1ed3fesdf279cd0c8edbdsf071sdgfac5561eb region=eu-west-2</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:ListIPSets</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">Unique ID of the detector that you want to retrieve</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<td style="width: 210px;">AWS.GuardDuty.Detectors.IPSet.IpSetId</td>
<td style="width: 503px;">Unique ID for the IPSet</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "DetectorId":"38b1ed3sadfe279cd0c8edb071asd5ac5561eb"
   },
   {  
      "IpSetId":"0eb1f4asd4bc5ed4720995f3esad4c4aad0266"
   }
]</pre>
<hr>
<h3 id="h_5495194414281528792590484">Create a threat intelligence set: aws-gd-create-threatintel-set</h3>
<p>Creates a list of known malicious IP addresses (ThreatIntelSet). GuardDuty generates findings based on ThreatIntelSets.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-create-threatintel-set format=TXT location=https://s3.eu-central-1.amazonaws.com/test/threatintel.txt activate=True detectorId=38b1ed3fe279czvasdd0c8edb0715azdsfc5561eb name=test region=eu-west-2</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:CreateThreatIntelSet</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">activate</td>
<td style="width: 535px;">A boolean value that indicates whether GuardDuty uses<br>the uploaded ThreatIntelSet</td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">Unique ID of the detector that you want to update</td>
</tr>
<tr>
<td style="width: 179px;">format</td>
<td style="width: 535px;">Format of the file that contains the ThreatIntelSet</td>
</tr>
<tr>
<td style="width: 179px;">location</td>
<td style="width: 535px;">URI of the file that contains the ThreatIntelSet, for example, https://s3.us-west-2.amazonaws.com/my-bucket/my-object-key</td>
</tr>
<tr>
<td style="width: 179px;">name</td>
<td style="width: 535px;">Friendly name for the ThreatIntelSet, which displays in all findings that are triggered by activities that involve IP addresses included in this ThreatIntelSet</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<td style="width: 210px;">AWS.GuardDuty.Detectors.ThreatIntelSet.ThreatIntelSetId</td>
<td style="width: 503px;">Unique identifier for a ThreatIntelSet</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "ThreatIntelSetId":"0eb1f4asd4bc5ed4720995f3esad4c4aad0266"
}</pre>
<hr>
<h3 id="h_420964804921528793220608">Delete a threat intelligence set: aws-gd-delete-threatintel-set</h3>
<p>Deletes a specified ThreatIntelSet ID. </p>
<h5>Command Example</h5>
<p><code>!aws-gd-delete-threatintel-set detectorId=38b1ed3fe279cd0c8edb0715ac5561eb threatIntelSetId=7eb1f440be5931f168280b574a26d44d region=eu-west-2</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:DeleteThreatIntelSet</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">activate</td>
<td style="width: 535px;">A boolean value that indicates whether GuardDuty uses<br>the uploaded ThreatIntelSet</td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">Unique ID of the detector that you want to update</td>
</tr>
<tr>
<td style="width: 179px;">format</td>
<td style="width: 535px;">Format of the file that contains the ThreatIntelSet</td>
</tr>
<tr>
<td style="width: 179px;">location</td>
<td style="width: 535px;">URI of the file that contains the ThreatIntelSet, for example, https://s3.us-west-2.amazonaws.com/my-bucket/my-object-key</td>
</tr>
<tr>
<td style="width: 179px;">name</td>
<td style="width: 535px;">Friendly name for the ThreatIntelSet, which displays in all findings that are triggered by activities that involve IP addresses included in this ThreatIntelSet</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<pre>The ThreatIntel Set <em>7eb1f440be5931f168280b574a26d44d</em> was deleted from Detector <em>38b1ed3fe279cd0c8edb0715ac5561eb</em>.</pre>
<hr>
<h3 id="h_5402018005611528793742779">Get threat intelligence set information: aws-gd-threatintel-set</h3>
<p>Retrieves the ThreatIntelSet specified by the ThreatIntelSet ID.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-get-threatintel-set detectorId=38b1ed3fe279cd0c8edb0715ac5561eb threatIntelSetId=7eb1f440be5931f168280b574a26d44d region=eu-west-2</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:GetThreatIntelSet</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">Unique ID of the detector that you want to update</td>
</tr>
<tr>
<td style="width: 179px;">threatIntelSetId</td>
<td style="width: 535px;">Unique ID that specifies the ThreatIntelSet that you want to describe</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<td style="width: 210px;">AWS.GuardDuty.Detectors.ThreatIntelSet.ThreatIntelSetId</td>
<td style="width: 503px;">The unique ID that specifies the ThreatIntelSet</td>
</tr>
<tr>
<td style="width: 210px;">AWS.GuardDuty.Detectors.ThreatIntelSet.Format</td>
<td style="width: 503px;">The format of the threatIntelSet</td>
</tr>
<tr>
<td style="width: 210px;">AWS.GuardDuty.Detectors.ThreatIntelSet.Location.Name</td>
<td style="width: 503px;">The URI of the file that contains the ThreatIntelSet</td>
</tr>
<tr>
<td style="width: 210px;">AWS.GuardDuty.Detectors.ThreatIntelSet.Name</td>
<td style="width: 503px;">Friendly ThreatIntelSet name</td>
</tr>
<tr>
<td style="width: 210px;">AWS.GuardDuty.Detectors.ThreatIntelSet.Status</td>
<td style="width: 503px;">Status of the uploaded threatIntelSet file</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "DetectorId":"38b1ed3fe279cd0c8edb0715ac5561eb",
   "ThreatIntelSetId":"7eb1f440be5931f168280b574a26d44d ",
   'Format':"TXT",
   'Location':"https://s3.eu-central-1.amazonaws.com/test/threatintel.txt",
   'Name':"Test",
   'Status':"DELETED"
}
</pre>
<hr>
<h3 id="h_121885886351528794056209">List all threat intelligence sets: aws-gd-list-threatintel-sets</h3>
<p>Lists all ThreatIntelSets in GuardDuty.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-list-threatintel-sets detectorId=38b1ed3fe279cd0c8edb0715ac5561eb region=eu-west-2</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:ListThreatIntelSet</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">The detectorID that specifies the GuardDuty service whose ThreatIntelSets you want to list</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<td style="width: 210px;">AWS.GuardDuty.Detectors.ThreatIntelSet.ThreatIntelSetId</td>
<td style="width: 503px;">The unique ID that specifies the ThreatIntelSet</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "DetectorId":"38b1ed3fe279cd0c8edb0715ac5561eb"
   },
   {  
      "ThreatIntelSetId":"7eb1f440be5931f168280b574a26d44d"
   }
]</pre>
<hr>
<h3 id="h_67638147141528795046616">Update a threat intelligence set: aws-gd-update-threatintel-set</h3>
<p>Updates a specified ThreatIntelSet ID. </p>
<h5>Command Example</h5>
<p><code>!aws-gd-update-threatintel-set detectorId=38b1ed3fe279cd0c8edb0715ac5561eb threatIntelSetId=7eb1f440be5931f168280b574a26d44d activate=False region=eu-west-2</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:UpdateThreatIntelSet</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">activate</td>
<td style="width: 535px;">The updated boolean value that specifies whether the ThreateIntelSet is active</td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">The detectorID that specifies the GuardDuty service whose ThreatIntelSet you want to update</td>
</tr>
<tr>
<td style="width: 179px;">threatIntelSetId</td>
<td style="width: 535px;">The unique ID that specifies the ThreatIntelSet that you want to update</td>
</tr>
<tr>
<td style="width: 179px;">location</td>
<td style="width: 535px;">URI of the file that contains the ThreatIntelSet, for example, https://s3.us-west-2.amazonaws.com/my-bucket/my-object-key</td>
</tr>
<tr>
<td style="width: 179px;">name</td>
<td style="width: 535px;">Friendly name for the ThreatIntelSet</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<pre>The ThreatIntel Set <em>7eb1f440be5931f168280b574a26d44d</em> was updated.</pre>
<hr>
<h3 id="h_151918107981528795343851">List Amazon GuardDuty findings for a specific detector: aws-gd-list-findings</h3>
<p>Lists all Amazon GuardDuty findings for the specified detector ID.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-list-findings detectorId=38b1ed3fe279cd0c8edb0715ac5561eb region=eu-west-2</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:ListFindings</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">The detectorID that specifies the GuardDuty service whose findings you want to list</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<td style="width: 210px;">AWS.GuardDuty.Findings.FindingId</td>
<td style="width: 503px;">Lists Amazon GuardDuty findings for the specified detector ID</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "FindingId":"2eb1ecee343f42b66b6f1a394dc3c21b"
   },
   {  
      "FindingId":"c6b180f7c27aff7ee204c7a2620a9cb3"
   },
   {  
      "FindingId":"e6b180f1d95d58f56a85e76c45a2cb34"
   },
   {  
      "FindingId":"f6b1d610567b6172bce359b564aba920"
   },
   {  
      "FindingId":"e6b180f1d22bdbcf4519004c9264f393"
   }
]</pre>
<hr>
<h3 id="h_939116898871528795749854">Describe Amazon GuardDuty findings for a specific detector: aws-gd-get-findings</h3>
<p>Describes Amazon GuardDuty findings specified by finding IDs.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-get-findings detectorIds=4f1fc7cd7dsg26sdf4328d8dc813 findingIds=96b1ac608sdf00e5183c3dds115c36aac328b,0ab180f5801sdg954418f3806c2a45282c9</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:GetFindings</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">The detectorID that specifies the GuardDuty service whose findings you want to retrieve</td>
</tr>
<tr>
<td style="width: 179px;">findingIds</td>
<td style="width: 535px;">IDs of the findings that you want to retrieve</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<pre>[  
   {  
      "AccountId":"123456789",
      "Arn":"arn:aws:guardduty:eu-central-1:123456789:detector/20b180e9f14sdgf1fc7cd7264sdg328d8dc813/finding/0ab180f580sdg1954418f3806c2a45282c9",
      "CreatedAt":"2018-04-26T12:26:08.306Z",
      "Description":"EC2 instance has an unprotected port which is being probed by a known malicious host.",
      "Id":"0ab180f5801954418f3806c2a45282c9",
      "Region":"eu-central-1",
      "Title":"Unprotected port on EC2 instance i-123456789 is being probed.",
      "Type":"Recon:EC2/PortProbeUnprotectedPort"
   },
   {  
      "AccountId":"123456789",
      "Arn":"arn:aws:guardduty:eu-central-1:123456789:detector/20b180e9sdgf14f1fc7cd7264dsg328d8dc813/finding/96b1ac60sdg800e5183csdg3d115c36aac328b",
      "CreatedAt":"2018-05-13T09:07:13.564Z",
      "Description":"EC2 instance has an unprotected port which is being probed by a known malicious host.",
      "Id":"96b1ac60800e5183c3d115c36aac328b",
      "Region":"eu-central-1",
      "Title":"Unprotected port on EC2 instance i-123456789 is being probed.",
      "Type":"Recon:EC2/PortProbeUnprotectedPort"
   }
]</pre>
<hr>
<h3 id="h_5612231099811528796201611">Generate example findings: aws-gd-create-sample-findings</h3>
<p>Generates example findings of types specified by the list of findings.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-create-sample-findings detectorId=4f1fc7cd7dsg2adf6sdf4328d8dc813 findingTypes=NULL region=eu-central-1</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:CreateSampleFindings</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">The ID of the detector to create sample findings for</td>
</tr>
<tr>
<td style="width: 179px;">findingTypes</td>
<td style="width: 535px;">Types of sample findings that you want to generate (separated with a comma ",")</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<pre>Sample Findings were generated.</pre>
<hr>
<h3 id="h_7397716710801528796473289">Archive Amazon GuardDuty findings: aws-gd-archive-findings</h3>
<p>Archives Amazon GuardDuty findings specified by the list of finding IDs.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-archive-findings detectorIds=4f1fc7cd7dsg26sdf4328d8dc813 findingIds=96b1ac608sdf00e5183c3dds115c36aac328b,0ab180f5801sdg954418f3806c2a45282c9</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:ArchiveFindings</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">The ID of the detector that specifies the GuardDuty service whose findings you want to archive</td>
</tr>
<tr>
<td style="width: 179px;">findingIds</td>
<td style="width: 535px;">Types of sample findings that you want to archive (separated with a comma ",")</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<pre>Findings were archived.</pre>
<hr>
<h3 id="h_90473052511841528796654452">Unarchive Amazon GuardDuty findings: aws-gd-unarchive-findings</h3>
<p>Unarchives Amazon GuardDuty findings specified by the list of finding IDs.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-unarchive-findings detectorIds=4f1fc7cd7dsg26sdf4328d8dc813 findingIds=96b1ac608sdf00e5183c3dds115c36aac328b,0ab180f5801sdg954418f3806c2a45282c9</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:UnarchiveFindings</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">The ID of the detector that specifies the GuardDuty service whose findings you want to unarchive</td>
</tr>
<tr>
<td style="width: 179px;">findingIds</td>
<td style="width: 535px;">Types of sample findings that you want to unarchive (separated with a comma ",")</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<pre>Findings were unarchived.</pre>
<hr>
<h3 id="h_65342598912931528796902361">Mark Amazon GuardDuty findings as useful or not useful: aws-gd-update-findings-feedback</h3>
<p>Marks the specified Amazon GuardDuty findings as useful or not useful.</p>
<h5>Command Example</h5>
<p><code>!aws-gd-update-findings-feedback detectorIds=4f1fc7cd7dsg26sdf4328d8dc813 findingIds=96b1ac608sdf00e5183c3dds115c36aac328b comments=Good Job feedback=USEFUL</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>guardduty:UpdateFindingsFeedback</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">detectorId</td>
<td style="width: 535px;">The ID of the detector that specifies the GuardDuty service whose findings you want to mark as useful or not useful</td>
</tr>
<tr>
<td style="width: 179px;">findingIds</td>
<td style="width: 535px;">Types of sample findings that you want to mark as useful or not useful (separated with a comma ",")</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
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
<pre>Findings feedback was sent.</pre>