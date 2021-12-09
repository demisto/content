![image](https://user-images.githubusercontent.com/49071222/72906531-0e452a00-3d3b-11ea-8703-8b97ddf30be0.png)


This integration lets you import **Palo Alto Networks - Prisma Cloud Compute** alerts into Cortex XSOAR

## Use Cases

- Manage Prisma Cloud Compute alerts in Cortex XSOAR.
- You can create new playbooks, or extend the default ones, to analyze alerts, assign tasks based on your analysis, and open tickets on other platforms.

## Configure Prisma Cloud Compute to Send Alerts to Cortex XSOAR

To send alerts from Prisma Cloud Compute to Cortex XSOAR, you need to create an alert profile.

1. Log in to your Prisma Cloud Compute console.
2. Navigate to **Manage > Alerts**.
3. Click **Add Profile** to create a new alert profile.
4. On the left, select **Demisto** from the provider list.
5. On the right, select the alert triggers. Alert triggers specify which alerts are sent to Cortex XSOAR.
6. Click **Save** to save the alert profile.

## Configure Cortex XSOAR

1. Navigate to **Settings > Integrations > Servers & Services**.
2. Search for **Prisma Cloud Compute**.
3. Click **Add instance** to create and configure a new integration.
   
   | Parameter Name | Description | Default |
   | -------------- | ----------- | ------- |
   | **Name** | A meaningful name for the integration instance. | Prisma Cloud Compute_&lt;alertProfileName&gt; |
   | **Fetches incidents** | Configures this integration instance to fetch alerts from Prisma Cloud Compute. | N/A |
   | **Prisma Cloud Compute Console URL** | URL address and port of your Prisma Cloud Compute console. Copy the address from the alert profile created in Prisma Cloud Compute. | https:/<span></span>/proxyserver.com |
   | **Prisma Cloud Compute Project Name (if applicable)** | Copy the project name from the alert profile created in Prisma Cloud Compute and enter paste in this field. | N/A |
   | **Trust any certificate (not secure)** | Skips verification of the CA certificate (not recommended). | N/A |
   | **Use system proxy settings** | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. | <span></span>https://proxyserver.com |
   | **Credentials** | Prisma Cloud Compute login credentials. | N/A |
   | **Prisma Cloud Compute CA Certificate** | CA Certificate used by Prisma Cloud Compute. Copy the certificate from the alert profile created in Prisma Cloud Compute. | N/A |
4. Click **Test** to validate the integration.
5. Click **Done** to save the integration.


## Using the Integration and Scripts

The integration ships with four default playbooks and four scripts that are used by the playbooks. The scripts encode the raw JSON alerts into Cortex XSOAR objects that can then be used in the playbooks. The scripts are:

* PrismaCloudComputeParseAuditAlert
* PrismaCloudComputeParseComplianceAlert
* PrismaCloudComputeParseVulnerabilityAlert
* PrismaCloudComputeParseCloudDiscoveryAlert


To better understand how playbooks and scripts interoperate, consider the _Prisma Cloud Compute - Vulnerability Alert_ playbook.

* When the playbook is triggered, the **Parse Vulnerability Alert** starts running.
* The task runs the **PrismaCloudComputeParseVulnerabilityAlert** script, which takes the `Prismacloudcomputerawalertjson` field of the incident (the raw JSON alert data) as input.

![image](https://user-images.githubusercontent.com/49071222/72902982-1601d000-3d35-11ea-8be2-a12ac8ea8862.png)


* Click **outputs** to see how the script transformed the raw JSON input into a Demisto object.


![image](https://user-images.githubusercontent.com/49071222/72903545-1189e700-3d36-11ea-9a35-81b756a5fc6d.png)


At this point, you can add tasks that extend the playbook to check and respond to alerts depending on the properties of the Demisto object.


## Troubleshooting

If any alerts are missing in Cortex XSOAR, check the status of the integration.

![image](https://user-images.githubusercontent.com/49071222/72086124-18b0fe00-330f-11ea-894b-6b2f9f0528fd.png)

### prisma-cloud-compute-profile-host-list
***
Get information about the hosts and their profile events, this command supports asterisks which allows you to get host profiles by filtering its fields according to a specific substring


#### Base Command

`prisma-cloud-compute-profile-host-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Hosts is the runtime profile hostname filter, semi comma separated values, for example !prisma-cloud-compute-profile-host-list hostname="*149*,*257*". | Optional | 
| limit | The maximum number of hosts and their profile events to return, must be between 1-50. Default is 15. | Optional | 
| offset | The offset number to begin listing hosts and their profile events. Default is 0. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.ProfileHost._id | Unknown | ID is the profile ID \(hostname\) | 
| PrismaCloudCompute.ProfileHost.accountID | String | AccountID is the cloud account ID associated with the profile | 
| PrismaCloudCompute.ProfileHost.apps | Unknown | Apps are the host's apps metadata | 
| PrismaCloudCompute.ProfileHost.collections | String | Collections is a list of collections to which this profile applies | 
| PrismaCloudCompute.ProfileHost.created | Date | Created is the profile creation time | 
| PrismaCloudCompute.ProfileHost.hash | Unknown | Hash is an uint32 hash associated with the profile | 
| PrismaCloudCompute.ProfileHost.labels | String | Labels are the labels associated with the profile | 
| PrismaCloudCompute.ProfileHost.sshEvents | Unknown | SSHEvents represents a list SSH events occurred on the host | 
| PrismaCloudCompute.ProfileHost.time | Date | Time is the last time when this profile was modified | 
| PrismaCloudCompute.ProfileHost.geoip | Unknown | geoip is the list of countries | 


#### Command Example
```!prisma-cloud-compute-profile-host-list hostName=*249*```

#### Human Readable Output

### Host Description
|Hostname|Distribution|Collections|
|---|---|---|
| 249-host-id | Ubuntu 16.04 | All,<br>676921422616 |
### Apps
|AppName|StartupProcess|User|LaunchTime|
|---|---|---|---|
| ssh | /usr/sbin/sshd | root | November 10, 2020 09:37:42 AM |
| docker | /usr/bin/dockerd | root | November 10, 2020 09:37:42 AM |
| atd | /usr/sbin/atd | root | November 10, 2020 09:37:42 AM |
| acpid | /usr/sbin/acpid | root | November 10, 2020 09:37:42 AM |
| cron | /usr/sbin/cron | root | November 10, 2020 09:37:42 AM |
|  | /usr/local//server |  | November 10, 2020 09:37:42 AM |
| apt-daily | /bin/dash | root | November 10, 2020 11:41:34 AM |
| snapd | /usr/lib/snapd/snapd | root | February 11, 2021 06:23:47 AM |
| systemd | /lib/systemd/systemd | root | September 02, 2021 10:25:30 AM |
### SSH Events
|User|Ip|ProcessPath|Command|Time|
|---|---|---|---|---|
| ubuntu | 1.1.1.1 | /usr/bin/clear_console | /usr/bin/clear_console -q | September 02, 2021 11:49:33 AM |
| ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -alF | September 02, 2021 11:04:01 AM |
| ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -alF | September 02, 2021 11:03:57 AM |
| ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -alF | September 02, 2021 11:03:53 AM |
| ubuntu | 1.1.1.1 | /usr/bin/dircolors | /usr/bin/dircolors | September 02, 2021 11:03:52 AM |
| ubuntu | 1.1.1.1 | /usr/bin/dirname | dirname /usr/bin/lesspipe | September 02, 2021 11:03:52 AM |
| ubuntu | 1.1.1.1 | /usr/bin/basename | basename /usr/bin/lesspipe | September 02, 2021 11:03:52 AM |
| ubuntu | 1.1.1.1 | /bin/dash | /bin/sh /usr/bin/lesspipe | September 02, 2021 11:03:52 AM |
| ubuntu | 1.1.1.1 | /usr/bin/groups | /usr/bin/groups | September 02, 2021 11:03:52 AM |
| ubuntu | 3.3.3.3 | /bin/bash | /bin/bash | September 02, 2021 11:03:52 AM |
| ubuntu | 1.1.1.1 | /bin/su | /bin/su | September 02, 2021 11:03:52 AM |
| ubuntu | 1.1.1.1 | /usr/bin/sudo | /usr/bin/sudo | September 02, 2021 11:03:52 AM |
| ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -lt | September 02, 2021 11:03:45 AM |
| ubuntu | 4.4.4.4 | /bin/ls | ls --color=auto -ltr | September 02, 2021 10:27:24 AM |
| ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -alF | September 02, 2021 10:27:22 AM |
| ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -alF | September 02, 2021 10:27:20 AM |
| ubuntu | 1.1.1.1 | /bin/ls | ls /etc/bash_completion.d | September 02, 2021 10:27:18 AM |
| ubuntu | 1.1.1.1 | /usr/bin/dircolors | /usr/bin/dircolors | September 02, 2021 10:27:18 AM |
| ubuntu | 5.5.5.5 | /usr/bin/dirname | dirname /usr/bin/lesspipe | September 02, 2021 10:27:18 AM |
| ubuntu | 1.1.1.1 | /usr/bin/basename | basename /usr/bin/lesspipe | September 02, 2021 10:27:18 AM |
| ubuntu | 1.1.1.1 | /bin/dash | /bin/sh /usr/bin/lesspipe | September 02, 2021 10:27:18 AM |
| ubuntu | 1.1.1.1 | /bin/ls | ls /etc/bash_completion.d | September 02, 2021 10:27:18 AM |
| ubuntu | 1.1.1.1 | /bin/bash | /bin/bash | September 02, 2021 10:27:18 AM |
| ubuntu | 4.4.4.4 | /usr/bin/scp | /usr/bin/scp | September 02, 2021 10:27:06 AM |
| ubuntu | 5.5.5.5 | /bin/bash | bash -c scp -t . | September 02, 2021 10:27:06 AM |
| root | 2.2.2.2 | /bin/sleep | /bin/sleep | September 02, 2021 10:26:52 AM |
| root | 2.2.2.2 | /bin/bash | bash -c echo 'Please login as the user "ubuntu" rather than the user "root".';echo;sleep 10 | September 02, 2021 10:26:52 AM |
| root | 1.1.1.1 | /bin/sleep | /bin/sleep | September 02, 2021 10:25:31 AM |
| root | 2.2.2.2 | /bin/bash | bash -c echo 'Please login as the user "ubuntu" rather than the user "root".';echo;sleep 10 | September 02, 2021 10:25:31 AM |


#### Command Example
```!prisma-cloud-compute-profile-host-list hostName=*249*,*163```

#### Human Readable Output

### Host Description
|Hostname|Distribution|Collections|
|---|---|---|
| 249-host-id | Ubuntu 16.04 | All,<br>676921422616 |
| 163-host-id | amzn 2 | All,<br>676921422616 |
### prisma-cloud-compute-profile-container-list
***
Get information about the containers and their profile events, this command supports asterisks which allows you to get container profiles by filtering its fields according to a specific substring


#### Base Command

`prisma-cloud-compute-profile-container-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster | Clusters is the runtime profile k8s cluster filter. | Optional | 
| id | IDs is the runtime profile id filter, semi comma separated values, for example !prisma-cloud-compute-profile-container-list id="*256*,*148*". | Optional | 
| image | Images is the runtime profile image filter, semi comma separated values, for example !prisma-cloud-compute-profile-container-list image="*console*,*defender*". | Optional | 
| image_id | ImageIDs is the runtime profile image id filter, semi comma separated values, for example !prisma-cloud-compute-profile-container-list image_id="*123*,*456*". | Optional | 
| namespace | Namespaces is the runtime profile k8s namespace filter, semi comma separated values, for example !prisma-cloud-compute-profile-container-list namespace="*namespace1*,*namespace2*". | Optional | 
| os | OS is the service runtime profile OS filter, semi comma separated values, for example !prisma-cloud-compute-profile-container-list os="*Red Hat*,*Windows*". | Optional | 
| state | States is the runtime profile state filter, semi comma separated values, for example !prisma-cloud-compute-profile-container-list state=*active*. | Optional | 
| limit | The maximum number of containers and their profile events, must be between 1-50. Default is 15. | Optional | 
| offset | The offset number to begin listing containers and their profile events. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.ProfileContainer._id | Unknown | Id is the profile ID | 
| PrismaCloudCompute.ProfileContainer.accountsIDs | String | AccountIDs are the cloud account IDs associated with the container runtime profile | 
| PrismaCloudCompute.ProfileContainer.archived | Boolean | Archive indicates whether this profile is archived | 
| PrismaCloudCompute.ProfileContainer.capabilities | Unknown | Capabilities are extended capabilities that are added to the profile based on static analysis | 
| PrismaCloudCompute.ProfileContainer.cluster | String | Cluster is the provided cluster name | 
| PrismaCloudCompute.ProfileContainer.collections | String | Collections are collections to which this profile applies | 
| PrismaCloudCompute.ProfileContainer.created | Date | Created is the profile creation time | 
| PrismaCloudCompute.ProfileContainer.entrypoint | String | Entrypoint is the image entrypoint | 
| PrismaCloudCompute.ProfileContainer.events | Unknown | Events are the last historical interactive process events for this profile, they are updated in a designated flow | 
| PrismaCloudCompute.ProfileContainer.filesystem | Unknown | Filesystem is the profile filesystem metadata | 
| PrismaCloudCompute.ProfileContainer.hash | Unknown | Hash is an uint32 hash associated with the profile | 
| PrismaCloudCompute.ProfileContainer.hostNetwork | Boolean | HostNetwork whether the instance share the network namespace with the host | 
| PrismaCloudCompute.ProfileContainer.hostPid | Boolean | HostPid indicates whether the instance share the pid namespace with the host | 
| PrismaCloudCompute.ProfileContainer.image | Boolean | description | 
| PrismaCloudCompute.ProfileContainer.imageID | String | ImageID is the profile's image ID | 
| PrismaCloudCompute.ProfileContainer.infra | Boolean | InfraContainer indicates this is an infrastructure container | 
| PrismaCloudCompute.ProfileContainer.istio | Boolean | Istio states whether it is an istio-monitored profile | 
| PrismaCloudCompute.ProfileContainer.k8s | Unknown | K8s holds Kubernetes related data | 
| PrismaCloudCompute.ProfileContainer.label | String | Label is the profile's label | 
| PrismaCloudCompute.ProfileContainer.lastUpdate | Date | Modified is the last time when this profile was modified | 
| PrismaCloudCompute.ProfileContainer.learnedStartup | Boolean | LearnedStartup indicates that startup events were learned | 
| PrismaCloudCompute.ProfileContainer.namespace | String | Namespace is the k8s deployment namespace | 
| PrismaCloudCompute.ProfileContainer.network | Unknown | Network is the profile networking metadata | 
| PrismaCloudCompute.ProfileContainer.os | Strubg | OS is the profile image OS | 
| PrismaCloudCompute.ProfileContainer.processes | Unknown | Processes is the profile processes metadata | 
| PrismaCloudCompute.ProfileContainer.relearningCause | String | RelearningCause is a string that describes the reasoning for a profile to enter the learning mode afterbeing activated | 
| PrismaCloudCompute.ProfileContainer.remainingLearningDurationSec | Number | RemainingLearningDurationSec represents the total time left that the system need to finish learning this image | 
| PrismaCloudCompute.ProfileContainer.state | Unknown | State is the current state of the profile. | 


#### Command Example
```!prisma-cloud-compute-profile-container-list id=*123*```

#### Human Readable Output

### Container Description
|ContainerID|Image|Os|State|Created|
|---|---|---|---|---|
| 123-container-id | twistlock/private:console_21_04_439 | Red Hat Enterprise Linux 8.4 (Ootpa) | active | September 02, 2021 11:05:08 AM |
### Processes
|Type|Path|DetectionTime|
|---|---|---|
| static | /usr/bin/mongodump | January 01, 0001 00:00:00 AM |
| static | /usr/bin/mongorestore | January 01, 0001 00:00:00 AM |
| static | /usr/bin/rpm | January 01, 0001 00:00:00 AM |
| static | /usr/bin/gpgconf | January 01, 0001 00:00:00 AM |
| static | /usr/bin/gpg-connect-agent | January 01, 0001 00:00:00 AM |
| static | /usr/bin/apt-get | January 01, 0001 00:00:00 AM |
| static | /usr/bin/apt-config | January 01, 0001 00:00:00 AM |
| static | /usr/bin/touch | January 01, 0001 00:00:00 AM |
| static | /usr/bin/dpkg | January 01, 0001 00:00:00 AM |
| static | /usr/bin/cmp | January 01, 0001 00:00:00 AM |
| static | /bin/cat | January 01, 0001 00:00:00 AM |
| static | /bin/rm | January 01, 0001 00:00:00 AM |
| static | /bin/readlink | January 01, 0001 00:00:00 AM |
| static | /bin/sed | January 01, 0001 00:00:00 AM |
| static | /bin/cp | January 01, 0001 00:00:00 AM |
| static | /bin/mktemp | January 01, 0001 00:00:00 AM |
| static | /bin/chmod | January 01, 0001 00:00:00 AM |
| static | /usr/bin/sort | January 01, 0001 00:00:00 AM |
| static | /usr/bin/test | January 01, 0001 00:00:00 AM |
| static | /usr/bin/find | January 01, 0001 00:00:00 AM |
| static | /usr/bin/gpgv | January 01, 0001 00:00:00 AM |
| static | /usr/bin/dirname | January 01, 0001 00:00:00 AM |
| static | /bin/sh | January 01, 0001 00:00:00 AM |
| static | /bin/echo | January 01, 0001 00:00:00 AM |
| static | /usr/bin/tar | January 01, 0001 00:00:00 AM |
| static | /usr/bin/sed | January 01, 0001 00:00:00 AM |
| static | /app/server | January 01, 0001 00:00:00 AM |
| behavioral | /usr/bin/mongod | September 02, 2021 11:05:08 AM |


#### Command Example
```!prisma-cloud-compute-profile-container-list id=*123*,*456*```

#### Human Readable Output
### Container Description
|ContainerID|Image|Os|State|Created|
|---|---|---|---|---|
| 123-container-id | twistlock/private:defender_21_04_439 | Red Hat Enterprise Linux 8.4 (Ootpa) | active | September 02, 2021 11:05:08 AM |
| 456-container-id | twistlock/private:console_21_04_439 | Red Hat Enterprise Linux 8.4 (Ootpa) | active | September 02, 2021 11:05:08 AM |

### prisma-cloud-compute-profile-container-hosts-list
***
Get the hosts where a specific container is running.


#### Base Command

`prisma-cloud-compute-profile-container-hosts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Container profile ID, can be retrieved from 'prisma-cloud-compute-profile-container-list' command. | Required | 
| limit | The maximum number of hosts to return, must be between 1-50. Default is 50. | Optional | 
| offset | The offset number to begin listing hosts of the container. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.ProfileContainerHost.containerID | String | Container ID | 
| PrismaCloudCompute.ProfileContainerHost.hostsIDs | Unknown | The container's host IDs. | 


#### Command Example
```!prisma-cloud-compute-profile-container-hosts-list id=123```

#### Human Readable Output
### Containers hosts list
|HostsIDs|
|---|
| host1,<br>host2 |

### prisma-cloud-compute-profile-container-forensic-list
***
Get runtime forensics data for a specific container on a specific host


#### Base Command

`prisma-cloud-compute-profile-container-forensic-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The container ID, can be retrieved from 'prisma-cloud-compute-profile-container-list' command. | Required | 
| collections | Collections are collections scoping the query. | Optional | 
| hostname | Hostname is the hostname for which data should be fetched. | Required | 
| incident_id | IncidentID is the incident ID in case the request kind is an incident. | Optional | 
| limit | maximum of forensics data records to return, must be between 1-50. Default is 20. | Optional | 
| offset | The offset number to begin listing records from. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.ContainerForensic.containerID | String | The container ID. | 
| PrismaCloudCompute.ContainerForensic.hostname | String | The Hostname. | 
| PrismaCloudCompute.ContainerForensic.Forensics.allPorts | Boolean | AllPorts indicates all listening ports are allowed | 
| PrismaCloudCompute.ContainerForensic.Forensics.attack | Unknown | Attack is the event attack type. | 
| PrismaCloudCompute.ContainerForensic.Forensics.category | Unknown | Category is the incident category. | 
| PrismaCloudCompute.ContainerForensic.Forensics.command | String | Command is the event command | 
| PrismaCloudCompute.ContainerForensic.Forensics.containerId | Unknown | ContainerID is the event container id | 
| PrismaCloudCompute.ContainerForensic.Forensics.dstIP | String | DstIP is the destination IP of the connection | 
| PrismaCloudCompute.ContainerForensic.Forensics.dstPort | Unknown | DstPort is the destination port | 
| PrismaCloudCompute.ContainerForensic.Forensics.dstProfileID | String | DstProfileID is the profile ID of the connection destination | 
| PrismaCloudCompute.ContainerForensic.Forensics.effect | String | Effect is the runtime audit effect | 
| PrismaCloudCompute.ContainerForensic.Forensics.listeningStartTime | Date | listeningStartTime is the port listening start time | 
| PrismaCloudCompute.ContainerForensic.Forensics.message | String | Message is the runtime audit message | 
| PrismaCloudCompute.ContainerForensic.Forensics.networkCollectionType | Unknown | NetworkCollectionType is the type of the network collection method | 
| PrismaCloudCompute.ContainerForensic.Forensics.outbound | Boolean | Outbound indicates if the port is outbound | 
| PrismaCloudCompute.ContainerForensic.Forensics.path | String | Path is the event path | 
| PrismaCloudCompute.ContainerForensic.Forensics.pid | Number | Pid is the event process id | 
| PrismaCloudCompute.ContainerForensic.Forensics.port | Number | Port is the listening port | 
| PrismaCloudCompute.ContainerForensic.Forensics.ppid | Number | PPid is the event parent process id | 
| PrismaCloudCompute.ContainerForensic.Forensics.process | String | Process is the event processdescription | 
| PrismaCloudCompute.ContainerForensic.Forensics.srcIP | String | SrcIP is the source IP of the connection | 
| PrismaCloudCompute.ContainerForensic.Forensics.srcProfileID | String | SrcProfileID is the profile ID of the connection source | 
| PrismaCloudCompute.ContainerForensic.Forensics.static | Boolean | Static indicates the event was added to the profile without behavioral indication | 
| PrismaCloudCompute.ContainerForensic.Forensics.type | Unknown | Type is the event type. | 
| PrismaCloudCompute.ContainerForensic.Forensics.timestamp | Boolean | Timestamp is the event timestamp | 
| PrismaCloudCompute.ContainerForensic.Forensics.user | Unknown | User is the event user | 


#### Command Example
```!prisma-cloud-compute-profile-container-forensic-list id=123 hostname=hostname1```

#### Human Readable Output

### Containers forensic report
|Type|Path|User|Pid|ContainerId|Timestamp|Command|
|---|---|---|---|---|---|---|
| Process spawned | /usr/bin/mongodump | twistlock | 7990 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 27398 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 14441 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 1421 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 20978 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 8044 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 27509 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 14633 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 1765 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 21338 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 8467 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 27998 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 15124 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 2230 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 21898 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 8668 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 28206 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 15330 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 2487 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 22080 | a6f769dd | January 01, 0001 00:00:00 AM | mongodump --out=/var/lib/twistlock-backup/dump |


### prisma-cloud-compute-host-forensic-list
***
Get forensics on a specific host


#### Base Command

`prisma-cloud-compute-host-forensic-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | host ID, can be retrieved from 'prisma-cloud-compute-profile-host-list' command. | Required | 
| collections | Collections are collections scoping the query. | Optional | 
| incident_id | IncidentID is the incident ID in case the request kind is an incident. | Optional | 
| limit | maximum of forensics data records to return, must be between 1-50. Default is 20. | Optional | 
| offset | The offset number to begin listing host forensics from. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.HostForensic.Forensics.app | String | App is the application associated with the event | 
| PrismaCloudCompute.HostForensic.Forensics.attack | Unknown | Attack is the event attack type | 
| PrismaCloudCompute.HostForensic.Forensics.category | Unknown | Category is the incident category. | 
| PrismaCloudCompute.HostForensic.Forensics.command | String | Command is the event command | 
| PrismaCloudCompute.HostForensic.Forensics.country | String | Country is the country associated with the event | 
| PrismaCloudCompute.HostForensic.Forensics.effect | String | Effect is the runtime audit effect | 
| PrismaCloudCompute.HostForensic.Forensics.interactive | Boolean | Interactive indicates if the event is interactive | 
| PrismaCloudCompute.HostForensic.Forensics.ip | String | IP is the IP address associated with the event | 
| PrismaCloudCompute.HostForensic.Forensics.listeningStartTime | Date | ListeningStartTime is the listening port start time | 
| PrismaCloudCompute.HostForensic.Forensics.message | String | Message is the runtime audit message | 
| PrismaCloudCompute.HostForensic.Forensics.path | String | Path is the event path | 
| PrismaCloudCompute.HostForensic.Forensics.pid | Number | Pid is the event process id | 
| PrismaCloudCompute.HostForensic.Forensics.port | Number | Port is the listening port | 
| PrismaCloudCompute.HostForensic.Forensics.ppath | String | P-path is the event parent path | 
| PrismaCloudCompute.HostForensic.Forensics.ppid | Number | PPid is the event parent process id | 
| PrismaCloudCompute.HostForensic.Forensics.process | String | Process is the event process | 
| PrismaCloudCompute.HostForensic.Forensics.timestamp | Date | Timestamp is the event timestamp | 
| PrismaCloudCompute.HostForensic.Forensics.type | Unknown | Type is the event type. | 
| PrismaCloudCompute.HostForensic.Forensics.user | Unknown | User is the event user | 
| PrismaCloudCompute.HostForensic.hostID | String | The host ID that was analyzed | 


#### Command Example
```!prisma-cloud-compute-host-forensic-list id=hostname```

#### Human Readable Output


### Host forensics report
|Type|Path|User|Pid|Timestamp|Command|App|
|---|---|---|---|---|---|---|
| Process spawned | /usr/bin/gawk | cakeagent | 29660 | December 08, 2021 18:16:04 PM | awk {gsub("%", "%%", $0);printf  $1 "\|" $2 "\|" $3 "\|" $4 "\|" $5 "\|" $6 "\|" $11 ":::"} | cron |
| Process spawned | /bin/ps | cakeagent | 29659 | December 08, 2021 18:16:04 PM | ps aux | cron |
| Process spawned | /usr/bin/gawk | cakeagent | 29657 | December 08, 2021 18:16:04 PM | awk { printf  $3 "\|" $2 "\|" $1 ":"} | cron |
| Process spawned | /bin/grep | cakeagent | 29656 | December 08, 2021 18:16:04 PM | grep -vE ^Filesystem\|tmpfs\|cdrom | cron |
| Process spawned | /bin/df | cakeagent | 29655 | December 08, 2021 18:16:04 PM | df -H -P -B G | cron |
| Process spawned | /usr/bin/gawk | cakeagent | 29653 | December 08, 2021 18:16:04 PM | awk {print $2} | cron |
| Process spawned | /bin/grep | cakeagent | 29652 | December 08, 2021 18:16:04 PM | grep total | cron |
| Process spawned | /bin/df | cakeagent | 29651 | December 08, 2021 18:16:04 PM | df -x tmpfs -x cdrom --total | cron |
| Process spawned | /usr/bin/gawk | cakeagent | 29649 | December 08, 2021 18:16:04 PM | awk {print $3} | cron |
| Process spawned | /bin/grep | cakeagent | 29648 | December 08, 2021 18:16:04 PM | grep total | cron |
| Process spawned | /bin/df | cakeagent | 29647 | December 08, 2021 18:16:04 PM | df -x tmpfs -x cdrom --total | cron |
| Process spawned | /bin/sed | cakeagent | 29644 | December 08, 2021 18:16:03 PM | sed -re s/.*:[ ]+([0-9.]*)%us,.*/\1/ | cron |
| Process spawned | /bin/grep | cakeagent | 29643 | December 08, 2021 18:16:03 PM | grep Cpu | cron |
| Process spawned | /usr/bin/top | cakeagent | 29642 | December 08, 2021 18:16:03 PM | top -b -n1 | cron |
| Process spawned | /bin/grep | cakeagent | 29639 | December 08, 2021 18:16:03 PM | grep MemTotal | cron |
| Process spawned | /bin/sed | cakeagent | 29640 | December 08, 2021 18:16:03 PM | sed -r s/MemTotal:.* ([0-9]+) kB/\1/ | cron |
| Process spawned | /bin/cat | cakeagent | 29638 | December 08, 2021 18:16:03 PM | cat /proc/meminfo | cron |
### prisma-cloud-compute-custom-feeds-ip-list
***
Get all the BlackListed IP addresses in the system


#### Base Command

`prisma-cloud-compute-custom-feeds-ip-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.CustomFeedIP._id | String | ID is the custom feed id | 
| PrismaCloudCompute.CustomFeedIP.digest | String | Digest is an internal digest of the custom ip feed | 
| PrismaCloudCompute.CustomFeedIP.feed | Unknown | Feed is the list of custom ips | 
| PrismaCloudCompute.CustomFeedIP.modified | Date | Modified is the last time the custom feed was modified | 


#### Command Example
```!prisma-cloud-compute-custom-feeds-ip-list```

#### Human Readable Output
### IP Feeds
|Modified|Feed|
|---|---|
| December 07, 2021 15:50:51 PM | 1.1.1.1,<br>2.2.2.2 |
### prisma-cloud-compute-custom-feeds-ip-add
***
Add a list of banned IPs to be blocked by the system


#### Base Command

`prisma-cloud-compute-custom-feeds-ip-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of custom ips to add to the banned IPs list that will be blocked, for example ip=1.1.1.1,2.2.2.2. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!prisma-cloud-compute-custom-feeds-ip-add ip=1.1.1.1,2.2.2.2```

#### Human Readable Output
Successfully updated the custom IP feeds
