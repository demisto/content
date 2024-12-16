Amazon Web Services Guard Duty Service Event Collector integration for Cortex XSIAM.

This is the default integration for this content pack when configured by the Data Onboarder in Cortex XSIAM.

## Configure AWS - GuardDuty Event Collector in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| AWS Default Region | The AWS Region for this instance of the integration. For example, us-west-2 | True |
| Role ARN | The Amazon Resource Name (ARN) role used for EC2 instance authentication. If this is used, an access key and secret key are not required. | False |
| Role Session Name | A descriptive name for the assumed role session. For example, xsiam-IAM.integration-Role_SESSION | False |
| Role Session Duration | The maximum length of each session in seconds. Default: 900 seconds. The Cortex XSOAR integration will have the permissions assigned only when the session is initiated and for the defined duration. | False |
| Access Key | The access key ID used for authentication, that was configured during IAM user configuration. If this is used, Role ARN is not required. | False |
| Secret Key | The secret key used for authentication, that was configured during IAM user configuration. If this is used, Role ARN is not required. | False |
| Timeout | The time in seconds until a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout preceded by a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 seconds will be used. | False |
| Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
| First fetch time | First fetch query `<number> <time unit>`, e.g., `7 days`. Default `3 days`. | False |
| Number of events to fetch per fetch. | Default is 10. | False |
| Guard Duty Severity level | The severity level or higher of findings to be fetched: Low, Medium, or High. For example, if you set the severity level to Medium, only findings with severity level Medium or High will be fetched. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
    

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### aws-gd-get-events
***
Manual command to fetch events and display them.


#### Base Command

`aws-gd-get-events`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| should_push_events | Set this argument to True to create events, otherwise the command will only display them. Possible values are: true, false. Default is false. | Required | 
| severity | The minimum severity of the events to fetch (inclusive). Possible values are: Low, Medium, High. Default is Low. | Required | 
| collect_from | The date to start collecting the events from. | Optional | 
| limit | The maximum amount of events to return. | Optional | 


#### Context Output

There is no context output for this command.

#### Command example
```!aws-gd-get-events severity=Low should_push_events=false limit=1 collect_from="60 days ago"```

#### Human Readable Output

##### AWSGuardDuty Logs
|Account Id|Arn|Created At|Description|Id|Partition|Region|Resource|Schema Version|Service|Severity|Title|Type|Updated At|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SomeAccountId | SomeArn | 2022-08-16T07:22:39.877Z | A container with a sensitive host path mounted inside was launched on EKS Cluster SomeFindingEKSClusterName. If this behavior is not expected, it may indicate that your credentials are compromised. | <some_id> | aws | <some_region> | EksClusterDetails: {"Name": "SomeFindingEKSClusterName", "Arn": "SomeFindingEKSClusterArn", "VpcId": "SomeFindingEKSClusterVpcId", "Status": "ACTIVE", "Tags": [{"Key": "SomeFindingEKSClusterTag1", "Value": "SomeFindingEKSClusterTagValue1"}, {"Key": "SomeFindingEKSClusterTag2", "Value": "SomeFindingEKSClusterTagValue2"}, {"Key": "SomeFindingEKSClusterTag3", "Value": "SomeFindingEKSClusterTagValue3"}], "CreatedAt": "2021-11-11T10:15:55.218000"}<br>KubernetesDetails: {"KubernetesUserDetails": {"Username": "SomeFindingUserName", "Uid": "SomeFindingUID", "Groups": ["SomeFindingUserGroup"]}, "KubernetesWorkloadDetails": {"Name": "SomeFindingKubernetesWorkloadName", "Type": "SomeFindingKubernetesWorkloadType", "Uid": "SomeFindingKubernetesWorkloadUID", "Namespace": "SomeFindingKubernetesWorkloadNamespace", "Containers": [{"Name": "SomeFindingContainerName", "Image": "SomeFindingContainerImage", "ImagePrefix": "SomeFindingContainerImagePrefix", "VolumeMounts": [{"Name": "SomeFindingVolumeName", "MountPath": "SomeFindingVolumeMountPath"}]}], "Volumes": [{"Name": "SomeFindingVolumeName", "HostPath": {"Path": "SomeFindingHostPath"}}]}}<br>ResourceType: EKSCluster | 2.0 | Action: {"ActionType": "KUBERNETES_API_CALL", "KubernetesApiCallAction": {"RequestUri": "SomeFindingRequestURI", "Verb": "create", "UserAgent": "", "RemoteIpDetails": {"City": {"CityName": "SomeFindingCityName"}, "Country": {"CountryName": "SomeFindingCountryName"}, "GeoLocation": {"Lat": 0, "Lon": 0}, "IpAddressV4": "1.1.1.1", "Organization": {"Asn": "0", "AsnOrg": "SomeFindingASNOrg", "Isp": "SomeFindingISP", "Org": "SomeFindingORG"}}, "StatusCode": 201}}<br>Archived: true<br>Count: 1<br>DetectorId: detectorid<br>EventFirstSeen: 2022-08-16T07:22:39.000Z<br>EventLastSeen: 2022-08-16T07:22:39.000Z<br>ResourceRole: TARGET<br>ServiceName: guardduty<br>AdditionalInfo: {"Value": "{\"sample\":true}", "Type": "default"} | 5 | Container launched with a sensitive host path mounted inside. | Persistence:Kubernetes/ContainerWithSensitiveMount | 2022-08-16T07:22:39.877Z |