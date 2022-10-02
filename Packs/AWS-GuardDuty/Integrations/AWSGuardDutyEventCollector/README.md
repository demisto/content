Amazon Web Services Guard Duty Service Event Collector integration for Cortex XSIAM.

## Configure AWS - GuardDuty Event Collector on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AWS - GuardDuty Event Collector.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | AWS Default Region |  | True |
    | Role ARN |  | False |
    | Role Session Name |  | False |
    | Role Session Duration |  | False |
    | Access Key |  | False |
    | Secret Key |  | False |
    | Password |  | False |
    | Timeout | The time in seconds until a timeout exception is reached. You can specify just the read timeout \(for example 60\) or also the connect timeout preceded by a comma \(for example 60,10\). If a connect timeout is not specified, a default of 10 seconds will be used. | False |
    | Retries | The maximum number of retry attempts when connection or throttling errors are encountered. Set to 0 to disable retries. The default value is 5 and the limit is 10. Note: Increasing the number of retries will increase the execution time. | False |
    | First fetch time |  | False |
    | Number of events to fetch per fetch. |  | False |
    | Guard Duty Severity level | The minimum severity of the events to fetch \(inclusive\). | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | The product corresponding to the integration that originated the events. |  | False |
    | The vendor name corresponding to the integration that originated the events. |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
