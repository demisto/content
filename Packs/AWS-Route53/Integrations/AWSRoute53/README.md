<!-- HTML_DOC -->
<p>Use this integration to manage your Amazon DNS web services.</p>
<p>We recommend that you use roles that have the following built-in AWS policies:</p>
<ul>
<li><em>Route53FullAccess</em></li>
<li><em>Route53ReadOnlyAccess</em></li>
</ul>
<h2>Prerequisites</h2>
<p>It is important that you familiarize yourself with and complete all steps detailed in the <a href="https://xsoar.pan.dev/docs/reference/articles/aws-integrations---authentication">AWS Integrations - Authentication</a>.</p>
<h2>Configure the Amazon Route 53 Integration on Demisto</h2>
<ol>
<li>Navigate to <strong>Settings</strong> &gt; <strong>Integrations</strong> &gt; <strong>Servers &amp; Services</strong>.</li>
<li>Search for AWS - Route53.</li>
<li>Click <strong>Add instance</strong> to create and configure a new integration instance.
<ul>
<li>Name: a textual name for the integration instance.</li>
<li>Role Arn</li>
<li>Role Session Name</li>
<li>Role Session Duration</li>
</ul>
</li>
<li>Click <strong>Test</strong> to validate the URLs and token.</li>
</ol>
<h2>Commands</h2>
<p>You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.</p>
<ol>
<li><a href="#h_84146649841528365012277">Create a record: aws-route53-create-record</a></li>
<li><a href="#h_85316223541528365019134">Delete a record: aws-route53-delete-record</a></li>
<li><a href="#h_7851351992891528365059776">Upsert a record: aws-route53-upsert-record</a></li>
<li><a href="#h_1443814561031528365025939">List all hosted zones: aws-route53-list-hosted-zones</a></li>
<li><a href="#h_8600922611511528365037618">List all resource record sets: aws-route53-list-resource-record-sets</a></li>
<li><a href="#h_8473130981981528365044198">Wait for successful record state: aws-route53-waiter-resource-record-sets-changed</a></li>
<li><a href="#h_540655102441528365052642">Test a DNS Answer: aws-route53-test-dns-answer</a></li>
</ol>
<hr>
<h3 id="h_84146649841528365012277">Create a record: aws-route53-create-record</h3>
<p>Creates a record in your Amazon Route 53 system.</p>
<h5>Command Example</h5>
<p><code>!aws-route53-create-record hostedZoneId=Z33ASF9#22MSFA6R6M5G9 source=test.example.com target=192.168.1.1 ttl=300 type=A comment="test record"</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br> Action: <em>route53:ChangeResourceRecordSets</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">source</td>
<td style="width: 535px;">Domain name you want to create, for example, www.example.com</td>
</tr>
<tr>
<td style="width: 179px;">target</td>
<td style="width: 535px;">DNS record value</td>
</tr>
<tr>
<td style="width: 179px;">ttl</td>
<td style="width: 535px;">Resource record cache time to live (TTL), in seconds</td>
</tr>
<tr>
<td style="width: 179px;">hostedZoneId</td>
<td style="width: 535px;">Hosted zone ID</td>
</tr>
<tr>
<td style="width: 179px;">type</td>
<td style="width: 535px;">Type of created to create</td>
</tr>
<tr>
<td style="width: 179px;">comment</td>
<td style="width: 535px;">Comments for the record creation</td>
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
   "Id":"/change/CSDFSASDASDM",
   "Status":"PENDING"
}</pre>
<hr>
<h3 id="h_85316223541528365019134">Delete a record: aws-route53-delete-record</h3>
<p>Deletes a record from your Amazon Route 53 system.</p>
<h5>Command Example</h5>
<pre>!aws-route53-delete-record hostedZoneId=Z33935452MA6RDSFDSG6M5G9 source=test.example.com target=192.168.1.1 type=A ttl=300</pre>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br> Action: <em>route53:ChangeResourceRecordSets</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">source</td>
<td style="width: 535px;">Domain name you want to delete, for example, www.example.com</td>
</tr>
<tr>
<td style="width: 179px;">target</td>
<td style="width: 535px;">DNS record value</td>
</tr>
<tr>
<td style="width: 179px;">ttl</td>
<td style="width: 535px;">Resource record cache time to live (TTL), in seconds</td>
</tr>
<tr>
<td style="width: 179px;">hostedZoneId</td>
<td style="width: 535px;">Hosted zone ID</td>
</tr>
<tr>
<td style="width: 179px;">type</td>
<td style="width: 535px;">Type of record to create</td>
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
   "Id":"/change/C1A79HK325D2sdf3FOI0J",
   "Status":"PENDING"
}
</pre>
<hr>
<h3 id="h_7851351992891528365059776">Upsert a record: aws-route53-upsert-record</h3>
<p>Create a new record if one does not exist, or update an existing article.</p>
<h5>Command Example</h5>
<p><code>!aws-route53-upsert-record hostedZoneId=Z33ASF9#22MSFA6R6M5G9 source=test.example.com target=192.168.1.2 ttl=300 type=A comment="test record"</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br> Action: <em>route53:ChangeResourceRecordSets</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">source</td>
<td style="width: 535px;">Name of the domain you want to create, for example www.example.com</td>
</tr>
<tr>
<td style="width: 179px;">target</td>
<td style="width: 535px;">DNS record value</td>
</tr>
<tr>
<td style="width: 179px;">ttl</td>
<td style="width: 535px;">Resource record cache time to live (TTL), in seconds</td>
</tr>
<tr>
<td style="width: 179px;">hostedZoneId</td>
<td style="width: 535px;">Hosted zone ID</td>
</tr>
<tr>
<td style="width: 179px;">type</td>
<td style="width: 535px;">The type of record to create</td>
</tr>
<tr>
<td style="width: 179px;">comment</td>
<td style="width: 535px;">Comments you want to include</td>
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
<td style="width: 503px;">Current state of the request. PENDING indicates that this request has not yet been applied to all Amazon Route 53 DNS servers</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSetsChange.Comment</td>
<td style="width: 503px;">A complex type that describes change information about changes made to your hosted zone</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "Id":"/change/CSDFSASDASDM",
   "Status":"PENDING"
}</pre>
<hr>
<h3 id="h_8473130981981528365044198">Wait for successful record state: aws-route53-waiter-resource-record-sets-changed</h3>
<p>A waiter function that waits until the record state is successful (Created, Deleted, Upsert).</p>
<h5>Command Example</h5>
<p><code>!aws-route53-waiter-resource-record-sets-changed id=CM3UDCRD3ZYDSAF41</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br> Action: <em>route53:GetChange</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">id</td>
<td style="width: 535px;">ID of the change</td>
</tr>
<tr>
<td style="width: 179px;">waiterDelay</td>
<td style="width: 535px;">Amount of time, in seconds, to wait between attempts (default is 30)</td>
</tr>
<tr>
<td style="width: 179px;">waiterMaxAttempts</td>
<td style="width: 535px;">Maximum number of attempts to make (default is 60)</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Context Output</h5>
<p>There is no context output for this command. </p>
<h5>Raw Output</h5>
<pre>success</pre>
<hr>
<h3 id="h_1443814561031528365025939">List all hosted zones: aws-route53-list-hosted-zones</h3>
<p>Returns a list of all hosted zones in your Amazon Route 53 system.</p>
<h5>Command Example</h5>
<p><code>!aws-route53-list-hosted-zones</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br> Action: <em>route53:ListHostedZones</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<thead>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
</thead>
<tbody>
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
<td style="width: 210px;">AWS.Route53.HostedZones.Id</td>
<td style="width: 503px;">Request ID</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.HostedZones.Name</td>
<td style="width: 503px;">Domain name</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.HostedZones.CallerReference</td>
<td style="width: 503px;">The value that you specified for CallerReference when you created the hosted zone</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.HostedZones.Config.Comment</td>
<td style="width: 503px;">Comments to include in the hosted zone</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.HostedZones.Config.PrivateZone</td>
<td style="width: 503px;">A value that indicates whether this is a private hosted zone.</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.HostedZones.ResourceRecordSetCount</td>
<td style="width: 503px;">The number of resource record sets in the hosted zone</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.HostedZones.LinkedService.ServicePrincipal</td>
<td style="width: 503px;">If the health check or hosted zone was created by another service, the service that created the resource</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.HostedZones.LinkedService.Description</td>
<td style="width: 503px;">If the health check or hosted zone was created by another service, an optional description that can be provided by the other service.</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[  
   {  
      "Id":"/hostedzone/Z3SDA392MSF6SFR6M5G9",
      "Name":"example.com.",
      "ResourceRecordSetCount":8
   }
]</pre>
<hr>
<h3 id="h_8600922611511528365037618">List all resource record sets: aws-route53-list-resource-record-sets</h3>
<p>Returns a list of all resource record sets in your Amazon Route 53 system.</p>
<h5>Command Example</h5>
<p><code>!aws-route53-list-resource-record-sets hostedZoneId=Z33DFSDDFSDF6R6MDF5G9</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br> Action: <em>route53:ListResourceRecordSets</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">hostedZoneId</td>
<td style="width: 535px;">Hosted zone ID</td>
</tr>
<tr>
<td style="width: 179px;">startRecordName</td>
<td style="width: 535px;">The first name in the lexicographic ordering of resource record sets that you want to list</td>
</tr>
<tr>
<td style="width: 179px;">startRecordType</td>
<td style="width: 535px;">The type of resource record set to begin the record listing from</td>
</tr>
<tr>
<td style="width: 179px;">startRecordIdentifier</td>
<td style="width: 535px;">Weighted resource record sets only</td>
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
<td style="width: 210px;"> AWS.Route53.RecordSets.Name</td>
<td style="width: 503px;"> Domain name</td>
</tr>
<tr>
<td style="width: 210px;"> AWS.Route53.RecordSets.Type</td>
<td style="width: 503px;">DNS record type</td>
</tr>
<tr>
<td style="width: 210px;"> AWS.Route53.RecordSets.SetIdentifier</td>
<td style="width: 503px;">An identifier that differentiates among multiple resource record sets that have the same combination of DNS name and type</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSets.Weight</td>
<td style="width: 503px;">Weighted resource record sets only</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSets.Region</td>
<td style="width: 503px;">Latency-based resource record sets only</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSets.GeoLocation.ContinentCode</td>
<td style="width: 503px;">The two-letter code for the continent</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSets.GeoLocation.CountryCode</td>
<td style="width: 503px;">The two-letter code for the country</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSets.GeoLocation.SubdivisionCode</td>
<td style="width: 503px;">The code for the subdivision, for example, a state in the United States or a province in Canada</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSets.Failover</td>
<td style="width: 503px;">Failover resource record sets only</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSets.MultiValueAnswer</td>
<td style="width: 503px;">Multivalue answer resource record sets only</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSets.TTL</td>
<td style="width: 503px;">Resource record cache time to live (TTL), in seconds</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSets.ResourceRecords.Value</td>
<td style="width: 503px;">Current record value</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSets.AliasTarget.HostedZoneId</td>
<td style="width: 503px;">Alias resource record sets only</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSets.AliasTarget.DNSName</td>
<td style="width: 503px;">Alias resource record sets only</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSets.AliasTarget.EvaluateTargetHealth</td>
<td style="width: 503px;">Alias resource record sets only</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSets.HealthCheckId</td>
<td style="width: 503px;">ID of the applicable health check</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.RecordSets.TrafficPolicyInstanceId</td>
<td style="width: 503px;">ID of the traffic policy instance that Amazon Route 53 created this resource record set for</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>[
{
"Name": "demistotest5.lab-demisto.com.",
"ResourceRecords": "192.168.1.1",
"TTL": 300,
"Type": "A"
},
{
"Name": "demistotest6.lab-demisto.com.",
"ResourceRecords": "192.168.1.1",
"TTL": 300,
"Type": "A"
}
]</pre>
<hr>
<h3 id="h_540655102441528365052642">Test a DNS answer: aws-route53-test-dns-answer</h3>
<p>Tests a DNS answer.</p>
<h5>Command Example</h5>
<p><code>!aws-route53-test-dns-answer hostedZoneId=Z339SDF2MA6R6ADFSM5G9 recordName=testing2.example.com recordType=A</code></p>
<h5>AWS IAM Policy Permission</h5>
<p>Effect: <em>Allow</em><br> Action: <em>route53:TestDNSAnswer</em></p>
<h5>Input</h5>
<table style="height: 287px; width: 741px;" border="2" cellpadding="6">
<tbody>
<tr>
<td style="width: 179px;"><strong> Parameter</strong></td>
<td style="width: 535px;"><strong>Description</strong></td>
</tr>
<tr>
<td style="width: 179px;">HostedZoneId</td>
<td style="width: 535px;">Hosted zone ID</td>
</tr>
<tr>
<td style="width: 179px;">recordName</td>
<td style="width: 535px;">Name of the resource record set that you want Amazon Route 53 to simulate a query for</td>
</tr>
<tr>
<td style="width: 179px;">RecordType</td>
<td style="width: 535px;">Resource record set type</td>
</tr>
<tr>
<td style="width: 179px;">resolverIP</td>
<td style="width: 535px;">If you want to simulate a request from a specific DNS resolver, specify the IP address for that resolver. If you omit this value, TestDnsAnswer uses the IP address of a DNS resolver in the AWS US East (N. Virginia) Region (us-east-1 )</td>
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
<td style="width: 210px;">AWS.Route53.TestDNSAnswer.Nameserver</td>
<td style="width: 503px;">Amazon Route 53 name server used to respond to the request</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.TestDNSAnswer.RecordName</td>
<td style="width: 503px;">Name of the resource record set that you submitted a request for</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.TestDNSAnswer.RecordType</td>
<td style="width: 503px;">The type of the resource record set that you submitted a request for</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.TestDNSAnswer.ResponseCode</td>
<td style="width: 503px;">A list that contains values that Amazon Route 53 returned for this resource record set</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.TestDNSAnswer.Protocol</td>
<td style="width: 503px;">A code that indicates whether the request is valid or not</td>
</tr>
<tr>
<td style="width: 210px;">AWS.Route53.TestDNSAnswer.RecordData</td>
<td style="width: 503px;">The protocol that Amazon Route 53 used to respond to the request, either UDP or TCP</td>
</tr>
</tbody>
</table>
<p> </p>
<h5>Raw Output</h5>
<pre>{  
   "Nameserver":"ns-311.awsdns-38.com",
   "Protocol":"UDP",
   "RecordName":"testing2.example.com",
   "RecordType":"A",
   "ResponseCode":"NOERROR"
}</pre>
<h3 id="h_7851351992891528365059776"> </h3>