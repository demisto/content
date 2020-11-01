<!-- HTML_DOC -->
<p>Use the AWS S3 integration to manage your AWS object storage. </p>
<p>This integration was integrated and tested with API Version 2012-11-05.</p>
<h2>Prerequisites</h2>
<p>It is important that you familiarize yourself with and complete all steps detailed in the <a href="https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication">AWS Integrations - Authentication</a>.</p>
<h2>Configure the AWS S3 Integration in Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for AWS - S3.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration.</li>
</ol><ul>
<li>
<strong>Name</strong>: a textual name for the integration instance.</li>
<li><strong>AWS Default Region</strong></li>
<li><strong>Role Arn</strong></li>
<li><strong>Role Session Name</strong></li>
<li><strong>Fetch incidents</strong></li>
<li><strong>Role Session Duration</strong></li>
<li><strong>Access Key</strong></li>
<li><strong>Secret Key</strong></li>
<li><strong>Use System Proxy</strong></li>
<li><strong>Trust any certificate (not secure)</strong></li>
</ul>

<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_14490777351528868375934">Create a bucket: aws-s3-create-bucket</a></li>
<li><a href="#h_3239675201528868603988">Delete a bucket: aws-s3-delete-bucket</a></li>
<li><a href="#h_839180213401528868859118">List all buckets in the AWS account: aws-s3-list-buckets</a></li>
<li><a href="#h_193623504651528869382003">Get the policy of a bucket: aws-s3-get-bucket-policy</a></li>
<li><a href="#h_343159300951528869576660">Delete a policy from a bucket: aws-s3-delete-bucket-policy</a></li>
<li><a href="#h_4978373091301528869946621">Download a file from a bucket to the War Room: aws-s3-download-file</a></li>
<li><a href="#h_5468051811701528870218939">List bucket objects: aws-s3-list-bucket-objects</a></li>
<li><a href="#h_570244652151528884288150">Assign a policy to a bucket: aws-s3-put-bucket-policy </a></li>
<li><a href="#h_234013965451538989509281">Upload a file: aws-s3-upload-file</a></li>
</ol>
<hr>
<h3 id="h_14490777351528868375934">1. Create a bucket</h3>
<p>Creates an AWS S3 bucket.</p>
<h5>Command Example</h5>
<p><code>!aws-s3-create-bucket bucket=test acl=private</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>s3:CreateBucket</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">bucket</td>
<td style="width: 535px;">Name of the S3 bucket to create (in lowercase)</td>
</tr>
<tr>
<td style="width: 179px;">acl</td>
<td style="width: 535px;">ACL for S3 bucket</td>
</tr>
<tr>
<td style="width: 179px;">locationConstraint</td>
<td style="width: 535px;">Specifies the region where the bucket is created. If you do not<br>specify a region, the bucket is created in US Standard.</td>
</tr>
<tr>
<td style="width: 179px;">grantFullControl</td>
<td style="width: 535px;">Allows grantee the read, write, read ACP, and write ACP permissions<br>on the bucket</td>
</tr>
<tr>
<td style="width: 179px;">grantRead</td>
<td style="width: 535px;">Allows grantee to list the objects in the bucket</td>
</tr>
<tr>
<td style="width: 179px;">grantReadACP</td>
<td style="width: 535px;">Allows grantee to read the bucket ACL</td>
</tr>
<tr>
<td style="width: 179px;">grantWrite</td>
<td style="width: 535px;">Allows grantee to create, overwrite, and delete any object in the bucket</td>
</tr>
<tr>
<td style="width: 179px;">grantWriteACP</td>
<td style="width: 535px;">Allows grantee to write the ACL for the applicable bucket</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name of the role to assum</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">An identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">The duration, in seconds, of the role session. The value can range from 900 seconds to the maximum session duration setting for the role.</td>
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
<td style="width: 210px;">AWS.S3.Bucket.BucketName</td>
<td style="width: 503px;">Name of the bucket that was created</td>
</tr>
<tr>
<td style="width: 210px;">AWS.S3.Bucket.Location</td>
<td style="width: 503px;">AWS Region the bucket was created</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "BucketName":"test",
      "Location":"test"
   }
]</pre>
<hr>
<h3 id="h_3239675201528868603988">2. Delete a bucket</h3>
<p>Deletes an AWS S3 bucket. You need to delete all objects in the bucket, including all object versions and delete markers, before you delete the bucket itself.</p>
<h5>Command Example</h5>
<p><code>!aws-s3-delete-bucket bucket=test</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>s3:DeleteBucket</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">bucket</td>
<td style="width: 535px;">Name of the S3 bucket to delete</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name of the role to assum</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">An identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">The duration, in seconds, of the role session. The value can range from 900 seconds to the maximum session duration setting for the role.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>The bucket was deleted.</pre>
<hr>
<h3 id="h_839180213401528868859118">3. List all buckets in the AWS account</h3>
<p>Lista all S3 buckets in the specified AWS account.</p>
<h5>Command Example</h5>
<p><code>!aws-s3-list-buckets</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>s3:ListBuckets</em></p>
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
<td style="width: 535px;">Amazon Resource Name of the role to assum</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">An identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">The duration, in seconds, of the role session. The value can range from 900 seconds to the maximum session duration setting for the role.</td>
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
<td style="width: 210px;">AWS.S3.Bucket.BucketName</td>
<td style="width: 503px;">Name of the bucket</td>
</tr>
<tr>
<td style="width: 210px;">AWS.S3.Buckets.CreationDate</td>
<td style="width: 503px;">Date the bucket was created</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "BucketName":"backup-lab",
      "CreationDate":"2018-04-29T13:31:57"
   },
   {  
      "BucketName":"cf-templates-1f85sad9zb6mmyna-ap-southeast-1",
      "CreationDate":"2018-05-06T06:34:30"
   },
   {  
      "BucketName":"cf-templates-1f859asfzb6mmyna-ap-southeast-2",
      "CreationDate":"2018-04-23T13:59:45"
   }
]</pre>
<hr>
<h3 id="h_193623504651528869382003">4. Get the policy of a bucket</h3>
<p>Get the policy associated with an AWS S3 bucket.</p>
<h5>Command Example</h5>
<p><code>!aws-s3-get-bucket-policy bucket=test</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>s3:GetBucketPolicy</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">bucket</td>
<td style="width: 535px;">Name of the bucket</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name of the role to assum</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">An identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">The duration, in seconds, of the role session. The value can range from 900 seconds to the maximum session duration setting for the role.</td>
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
<td style="width: 210px;">AWS.S3.Bucket.Policy.Version</td>
<td style="width: 503px;">S3 bucket policy version</td>
</tr>
<tr>
<td style="width: 210px;">AWS.S3.Bucket.Policy.PolicyID</td>
<td style="width: 503px;">S3 bucket policy ID</td>
</tr>
<tr>
<td style="width: 210px;">AWS.S3.Bucket.Policy.Sid</td>
<td style="width: 503px;">S3 bucket policy statment ID</td>
</tr>
<tr>
<td style="width: 210px;">AWS.S3.Bucket.Policy.Action</td>
<td style="width: 503px;">S3 bucket policy statement action</td>
</tr>
<tr>
<td style="width: 210px;">AWS.S3.Bucket.Policy.Principal</td>
<td style="width: 503px;">S3 bucket policy statement principal</td>
</tr>
<tr>
<td style="width: 210px;">AWS.S3.Bucket.Policy.Resource</td>
<td style="width: 503px;">S3 bucket policy statement resource</td>
</tr>
<tr>
<td style="width: 210px;">AWS.S3.Bucket.Policy.Effect</td>
<td style="width: 503px;">S3 bucket policy statement effect</td>
</tr>
<tr>
<td style="width: 210px;">AWS.S3.Bucket.Policy.Json</td>
<td style="width: 503px;">AWS S3 policy JSON output</td>
</tr>
<tr>
<td style="width: 210px;">AWS.S3.Bucket.Policy.BucketName</td>
<td style="width: 503px;">S3 bucket name</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "Action":"s3:",
      "BucketName":null,
      "Effect":"Allow",
      "PolicyId":"Policy1519234481415511",
      "PolicyVersion":"2012-10-17",
      "Principal":{  
         "AWS":"arn:aws:iam::123456789:user/itai"
      },
      "Resource":"arn:aws:s3:::test",
      "Sid":"Stmt1519481385324929"
   },
   {  
      "Action":"s3:",
      "BucketName":null,
      "Effect":"Allow",
      "PolicyId":"Policy15194324581415511",
      "PolicyVersion":"2012-10-17",
      "Principal":{  
         "AWS":"arn:aws:iam::123456789:user/bob"
      },
      "Resource":"arn:aws:s3:::test",
      "Sid":"Stmt1519481434214395"
   }
]</pre>
<hr>
<h3 id="h_343159300951528869576660">5. Delete a policy from a bucket</h3>
<p>Deletes a policy from an Amazon S3 bucket.</p>
<h5>Command Example</h5>
<p><code>!aws-s3-delete-bucket-policy bucket=test</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>s3:DeleteBucketPolicy</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">bucket</td>
<td style="width: 535px;">Name of the S3 bucket</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name of the role to assum</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">An identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">The duration, in seconds, of the role session. The value can range from 900 seconds to the maximum session duration setting for the role.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>Policy deleted from <em>test</em>.</pre>
<hr>
<h3 id="h_4978373091301528869946621">6. Download a file from a bucket to the War Room</h3>
<p>Downloads a file from an Amazon S3 bucket to the Demisto War Room.</p>
<h5>Command Example</h5>
<p><code>!aws-s3-download-file bucket=test key=test.txt</code></p>
<h5>AWS S3 Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>s3:DownloadFile</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">bucket</td>
<td style="width: 535px;">Name of the S3 bucket</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name of the role to assum</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">An identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">The duration, in seconds, of the role session. The value can range from 900 seconds to the maximum session duration setting for the role.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<p>There is no raw output for this command.</p>
<hr>
<h3 id="h_5468051811701528870218939">7. List bucket objects</h3>
<p>List all bucket objects in the AWS account.</p>
<h5>Command Example</h5>
<p><code>!aws-s3-list-bucket-objects bucket=test</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>s3:GetObject</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">bucket</td>
<td style="width: 535px;">Name of the S3 bucket</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name of the role to assum</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">An identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">The duration, in seconds, of the role session. The value can range from 900 seconds to the maximum session duration setting for the role.</td>
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
<td style="width: 210px;">AWS.S3.BucketObjects.Key</td>
<td style="width: 503px;">Name of the S3 object</td>
</tr>
<tr>
<td style="width: 210px;">AWS.S3.BucketObjects.Size</td>
<td style="width: 503px;">Object size</td>
</tr>
<tr>
<td style="width: 210px;">AWS.S3.BucketObjects.LastModified</td>
<td style="width: 503px;">Last date the object was modified</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "BucketName":"test",
      "Key":"demi2018-04-05-14-29-49-76DA472F25CB951F",
      "LastModified":"2018-04-05T14:29:51",
      "Size":"323.0 B"
   },
   {  
      "BucketName":"test",
      "Key":"demi2018-04-05-15-23-20-32C6A7DEA888F497",
      "LastModified":"2018-04-05T15:23:21",
      "Size":"367.0 B"
   },
   {  
      "BucketName":"test",
      "Key":"demi2018-04-05-15-37-12-8735352AFBA6932E",
      "LastModified":"2018-04-05T15:37:14",
      "Size":"326.0 B"
   },
   {  
      "BucketName":"test",
      "Key":"demi2018-04-05-16-25-46-C891B9F069DE83C6",
      "LastModified":"2018-04-05T16:25:47",
      "Size":"326.0 B"
   },
   {  
      "BucketName":"test",
      "Key":"demi2018-04-05-16-36-44-69C802DCC5563A44",
      "LastModified":"2018-04-05T16:36:45",
      "Size":"368.0 B"
   }
]</pre>
<hr>
<h3 id="h_570244652151528884288150">8. Assign a policy to a bucket</h3>
<p>Assign a policy to an Amazon S3 bucket.</p>
<h5>Command Example</h5>
<p><code>!aws-s3-put-bucket-policy bucket=test policy={"Version":"2012-10-17","Id":"Policy1519481415511","Statement":[{"Sid":"Stmt1519ds34548138sf5929","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789:user/itai"},"Action":"s3:","Resource":"arn:aws:s3:::test"},{"Sid":"Stmt1345519481414395","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789:user/bob"},"Action":"s3:","Resource":"arn:aws:s3:::test"}]}</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br>Action: <em>s3:PutBucketPolicy</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">bucket</td>
<td style="width: 535px;">Name of the S3 bucket</td>
</tr>
<tr>
<td style="width: 179px;">policy</td>
<td style="width: 535px;">Bucket policy to apply (in JSON format)</td>
</tr>
<tr>
<td style="width: 179px;">confirmRemoveSelfBucketAccess</td>
<td style="width: 535px;">Set this parameter to <em>true</em> to confirm that you want to remove your permissions to change this bucket policy in the future</td>
</tr>
<tr>
<td style="width: 179px;">region</td>
<td style="width: 535px;">AWS region (if not specified, the default region is used)</td>
</tr>
<tr>
<td style="width: 179px;">roleArn</td>
<td style="width: 535px;">Amazon Resource Name of the role to assum</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionName</td>
<td style="width: 535px;">An identifier for the assumed role session</td>
</tr>
<tr>
<td style="width: 179px;">roleSessionDuration</td>
<td style="width: 535px;">The duration, in seconds, of the role session. The value can range from 900 seconds to the maximum session duration setting for the role.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<p> </p>
<h5>Raw Output</h5>
<pre>Successfully applied bucket policy to <em>test</em> bucket.</pre>
<h3 id="h_234013965451538989509281">9. Upload a file</h3>
<hr>
<p>Upload a file to an AWS S3 bucket.</p>
<h5>Base Command</h5>
<pre><code>aws-s3-upload-file</code></pre>
<h5>Input</h5>
<table style="width: 748px;" border="2" cellpadding="6">
<thead>
<tr>
<th style="width: 142px;"><strong>Argument Name</strong></th>
<th style="width: 495px;"><strong>Description</strong></th>
<th style="width: 71px;"><strong>Required</strong></th>
</tr>
</thead>
<tbody>
<tr>
<td style="width: 142px;">entryID</td>
<td style="width: 495px;">Entry ID of the file to upload</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 142px;">bucket</td>
<td style="width: 495px;">The name of the bucket to upload to</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 142px;">key</td>
<td style="width: 495px;">The name of the key to upload to</td>
<td style="width: 71px;">Required</td>
</tr>
<tr>
<td style="width: 142px;">region</td>
<td style="width: 495px;">The AWS Region, if not specified the default region will be used.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 142px;">roleArn</td>
<td style="width: 495px;">The Amazon Resource Name (ARN) of the role to assume.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 142px;">roleSessionName</td>
<td style="width: 495px;">An identifier for the assumed role session.</td>
<td style="width: 71px;">Optional</td>
</tr>
<tr>
<td style="width: 142px;">roleSessionDuration</td>
<td style="width: 495px;">The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role.</td>
<td style="width: 71px;">Optional</td>
</tr>
</tbody>
</table>
<h5> </h5>
<h5>Context Output</h5>
<p>There is no context output for this command.</p>
<h5>Command Example</h5>
<pre>!aws-s3-upload-file bucket="bucket name" key="file name to be displayed" entryID=##@##</pre>
<h5>Context Example</h5>
<h5>Human Readable Output</h5>
<p><a href="https://user-images.githubusercontent.com/41998709/46463978-f1938480-c7cd-11e8-92f5-368f61d9d4ae.png" target="_blank" rel="noopener noreferrer"><img src="https://user-images.githubusercontent.com/41998709/46463978-f1938480-c7cd-11e8-92f5-368f61d9d4ae.png" alt="human readable output" width="749" height="78"></a></p>