Amazon Web Services Managed Cloud DNS Service.

## Configure AWS - Route53 in Cortex


| **Parameter** | **Required** |
| --- | --- |
| Role Arn | False |
| Role Session Name | False |
| Role Session Duration | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aws-route53-create-record
***
Creates a resource record set. Creates a resource record set that has the specified values.


#### Base Command

`aws-route53-create-record`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source | The name of the domain you want to Create. i.e. www.example.com. | Required | 
| target | The DNS record value. | Required | 
| ttl | The resource record cache time to live (TTL), in seconds. | Required | 
| hostedZoneId | Specify the hosted zone ID. | Required | 
| type | The type of the record to create. Possible values are: A, AAAA, CAA, CNAME, MX, NAPTR, NS, PTR, SOA, SPF, SRV, TX. | Required | 
| comment | Any comments you want to include. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Route53.RecordSetsChange.Id | string | The ID of the request. | 
| AWS.Route53.RecordSetsChange.Status | string | The current state of the request. PENDING indicates that this request has not yet been applied to all Amazon Route 53 DNS servers. | 
| AWS.Route53.RecordSetsChange.Comment | string | A complex type that describes change information about changes made to your hosted zone. | 

#### Command Example
``` !aws-route53-create-record hostedZoneId=Z33ASF9#22MSFA6R6M5G9 source=test.example.com target=192.168.1.1 ttl=300 type=A comment="test record"```

### aws-route53-delete-record
***
Deletes a resource record set. Deletes an existing resource record set that has the specified values.


#### Base Command

`aws-route53-delete-record`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source | The name of the domain you want to Create. i.e. www.example.com. | Required | 
| target | The DNS record value. | Required | 
| ttl | The resource record cache time to live (TTL), in seconds. | Required | 
| hostedZoneId | Specify the hosted zone ID. | Required | 
| type | The type of the record to create. Possible values are: A, AAAA, CAA, CNAME, MX, NAPTR, NS, PTR, SOA, SPF, SRV, TX. | Required | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Route53.RecordSetsChange.Id | string | The ID of the request. | 
| AWS.Route53.RecordSetsChange.Status | string | The current state of the request. PENDING indicates that this request has not yet been applied to all Amazon Route 53 DNS servers. | 
| AWS.Route53.RecordSetsChange.Comment | string | A complex type that describes change information about changes made to your hosted zone. |

#### Command Example
```!aws-route53-delete-record hostedZoneId=Z33935452MA6RDSFDSG6M5G9 source=test.example.com target=192.168.1.1 type=A ttl=300 ```

### aws-route53-list-hosted-zones
***
Retrieves a list of the public and private hosted zones that are associated with the current AWS account. 


#### Base Command

`aws-route53-list-hosted-zones`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Route53.HostedZones.Id | string | The ID that Amazon Route 53 assigned to the hosted zone when you created it. | 
| AWS.Route53.HostedZones.Name | string | The name of the domain. | 
| AWS.Route53.HostedZones.CallerReference | string | The value that you specified for CallerReference when you created the hosted zone. | 
| AWS.Route53.HostedZones.Config.Comment | string | Any comments that you want to include about the hosted zone. | 
| AWS.Route53.HostedZones.Config.PrivateZone | string | A value that indicates whether this is a private hosted zone. | 
| AWS.Route53.HostedZones.ResourceRecordSetCount | number | The number of resource record sets in the hosted zone. | 
| AWS.Route53.HostedZones.LinkedService.ServicePrincipal | string | If the health check or hosted zone was created by another service, the service that created the resource.  | 
| AWS.Route53.HostedZones.LinkedService.Description | string | If the health check or hosted zone was created by another service, an optional description that can be provided by the other service.  | 

#### Command Example
```!aws-route53-list-hosted-zones```

### aws-route53-list-resource-record-sets
***
Lists the resource record sets in a specified hosted zone.


#### Base Command

`aws-route53-list-resource-record-sets`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostedZoneId | The ID of the hosted zone that contains the resource record sets that you want to list. | Required | 
| startRecordName |  The first name in the lexicographic ordering of resource record sets that you want to list. | Optional | 
| startRecordType | The type of resource record set to begin the record listing from. Possible values are: SOA, A, TXT, NS, CNAME, MX, NAPTR, PTR, SRV, SPF, AAAA, CAA. | Optional | 
| startRecordIdentifier | Weighted resource record sets only. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Route53.RecordSets.Name | string | The name of the domain. | 
| AWS.Route53.RecordSets.Type | string | The DNS record type. | 
| AWS.Route53.RecordSets.SetIdentifier | string | An identifier that differentiates among multiple resource record sets that have the same combination of DNS name and type.  | 
| AWS.Route53.RecordSets.Weight | number | Weighted resource record sets only. | 
| AWS.Route53.RecordSets.Region | string | Latency-based resource record sets only | 
| AWS.Route53.RecordSets.GeoLocation.ContinentCode | string | The two-letter code for the continent. | 
| AWS.Route53.RecordSets.GeoLocation.CountryCode | string | The two-letter code for the country. | 
| AWS.Route53.RecordSets.GeoLocation.SubdivisionCode | string | The code for the subdivision, for example, a state in the United States or a province in Canada. | 
| AWS.Route53.RecordSets.Failover | string | Failover resource record sets only | 
| AWS.Route53.RecordSets.MultiValueAnswer | string | Multivalue answer resource record sets only | 
| AWS.Route53.RecordSets.TTL | string | The resource record cache time to live \(TTL\), in seconds. | 
| AWS.Route53.RecordSets.ResourceRecords.Value | string | The current  record value. | 
| AWS.Route53.RecordSets.AliasTarget.HostedZoneId | string | Alias resource record sets only | 
| AWS.Route53.RecordSets.AliasTarget.DNSName | string | Alias resource record sets only | 
| AWS.Route53.RecordSets.AliasTarget.EvaluateTargetHealth | string | Alias resource record sets only | 
| AWS.Route53.RecordSets.HealthCheckId | string | ID of the applicable health check. | 
| AWS.Route53.RecordSets.TrafficPolicyInstanceId | string | the ID of the traffic policy instance that Amazon Route 53 created this resource record set for. | 


#### Command Example
```!aws-route53-list-resource-record-sets hostedZoneId=Z33DFSDDFSDF6R6MDF5G9```

### aws-route53-waiter-resource-record-sets-changed
***
A waiter function that waits until record set change is successful


#### Base Command

`aws-route53-waiter-resource-record-sets-changed`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID of the change. | Required | 
| waiterDelay | The amount of time in seconds to wait between attempts. Default: 30. | Optional | 
| waiterMaxAttempts | The maximum number of attempts to be made. Default: 60. | Optional | 


#### Context Output

There is no context output for this command.


#### Command Example
```!aws-route53-waiter-resource-record-sets-changed id=CM3UDCRD3ZYDSAF41```


### aws-route53-test-dns-answer
***
Gets the value that Amazon Route 53 returns in response to a DNS request for a specified record name and type. You can optionally specify the IP address of a DNS resolver, an EDNS0 client subnet IP address, and a subnet mask.


#### Base Command

`aws-route53-test-dns-answer`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostedZoneId | The ID of the hosted zone that you want Amazon Route 53 to simulate a query for. | Required | 
| recordName | The name of the resource record set that you want Amazon Route 53 to simulate a query for. | Required | 
| recordType | The type of the resource record set. Possible values are: SOA, A, TXT, NS, CNAME, MX, NAPTR, PTR, SRV, SPF, AAAA, CAA. | Required | 
| resolverIP | If you want to simulate a request from a specific DNS resolver, specify the IP address for that resolver. If you omit this value, TestDnsAnswer uses the IP address of a DNS resolver in the AWS US East (N. Virginia) Region (us-east-1 ). | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Route53.TestDNSAnswer.Nameserver | string | The Amazon Route 53 name server used to respond to the request. | 
| AWS.Route53.TestDNSAnswer.RecordName | string | The name of the resource record set that you submitted a request for. | 
| AWS.Route53.TestDNSAnswer.RecordType | string | The type of the resource record set that you submitted a request for. | 
| AWS.Route53.TestDNSAnswer.ResponseCode | string | A list that contains values that Amazon Route 53 returned for this resource record set. | 
| AWS.Route53.TestDNSAnswer.Protocol | string | A code that indicates whether the request is valid or not. | 
| AWS.Route53.TestDNSAnswer.RecordData | string | The protocol that Amazon Route 53 used to respond to the request, either UDP or TCP . | 

#### Command Example
```!aws-route53-test-dns-answer hostedZoneId=Z339SDF2MA6R6ADFSM5G9 recordName=testing2.example.com recordType=A```

### aws-route53-upsert-record
***
Upsert a resource record set. If a resource record set does not already exist, AWS creates it. If a resource set does exist, Amazon Route 53 updates it with the values in the request.


#### Base Command

`aws-route53-upsert-record`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| source | The name of the domain you want to Create. i.e. www.example.com. | Required | 
| target | The DNS record value. | Required | 
| ttl | The resource record cache time to live (TTL), in seconds. | Required | 
| hostedZoneId | Specify the hosted zone ID. | Required | 
| type | The type of the record to create. Possible values are: A, AAAA, CAA, CNAME, MX, NAPTR, NS, PTR, SOA, SPF, SRV, TX. | Required | 
| comment | Any comments you want to include. | Optional | 
| roleArn | The Amazon Resource Name (ARN) of the role to assume. | Optional | 
| roleSessionName | An identifier for the assumed role session. | Optional | 
| roleSessionDuration | The duration, in seconds, of the role session. The value can range from 900 seconds (15 minutes) up to the maximum session duration setting for the role. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AWS.Route53.RecordSetsChange.Id | string | The ID of the request. | 
| AWS.Route53.RecordSetsChange.Status | string | The current state of the request. PENDING indicates that this request has not yet been applied to all Amazon Route 53 DNS servers. | 
| AWS.Route53.RecordSetsChange.Comment | string | A complex type that describes change information about changes made to your hosted zone. | 

#### Command Example
```!aws-route53-upsert-record hostedZoneId=Z33ASF9#22MSFA6R6M5G9 source=test.example.com target=192.168.1.2 ttl=300 type=A comment="test record"```