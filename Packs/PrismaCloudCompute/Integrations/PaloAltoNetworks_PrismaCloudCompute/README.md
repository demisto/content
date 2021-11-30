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
* The task runs the **PrismaCloudComputeParseVulnerabilityAlert** script, which takes the `prismacloudcomputerawalertjson` field of the incident (the raw JSON alert data) as input.

![image](https://user-images.githubusercontent.com/49071222/72902982-1601d000-3d35-11ea-8be2-a12ac8ea8862.png)


* Click **outputs** to see how the script transformed the raw JSON input into a Demisto object.


![image](https://user-images.githubusercontent.com/49071222/72903545-1189e700-3d36-11ea-9a35-81b756a5fc6d.png)


At this point, you can add tasks that extend the playbook to check and respond to alerts depending on the properties of the Demisto object.


## Troubleshooting

If any alerts are missing in Cortex XSOAR, check the status of the integration.

![image](https://user-images.githubusercontent.com/49071222/72086124-18b0fe00-330f-11ea-894b-6b2f9f0528fd.png)

### prisma-cloud-compute-profile-host-list
***
Get information about the hosts and their profile events.


#### Base Command

`prisma-cloud-compute-profile-host-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster | Clusters is the runtime profile k8s cluster filter. | Optional | 
| hostName | Hosts is the runtime profile hostname filter. | Optional | 
| id | IDs is the runtime profile id filter. | Optional | 
| image | Images is the runtime profile image filter. | Optional | 
| namespace | Namespaces is the runtime profile k8s namespace filter. | Optional | 
| os | OS is the service runtime profile OS filter. | Optional | 
| state | States is the runtime profile state filter. | Optional | 
| limit | The maximum number of hosts and their profile events to return. Default is 15. . Default is 15. | Optional | 
| offset | The offset number to begin listing hosts and their profile events. Default is 0. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| prismaCloudCompute.profileHost_.id | Unknown | ID is the profile ID \(hostname\) | 
| prismaCloudCompute.profileHost.accountID | String | AccountID is the cloud account ID associated with the profile | 
| prismaCloudCompute.profileHost.apps | Unknown | Apps are the host's apps metadata | 
| prismaCloudCompute.profileHost.collections | String | Collections is a list of collections to which this profile applies | 
| prismaCloudCompute.profileHost.created | Date | Created is the profile creation time | 
| prismaCloudCompute.profileHost.hash | Unknown | Hash is an uint32 hash associated with the profile | 
| prismaCloudCompute.profileHost.labels | String | Labels are the labels associated with the profile | 
| prismaCloudCompute.profileHost.sshEvents | Unknown | SSHEvents represents a list SSH events occurred on the host | 
| prismaCloudCompute.profileHost.time | Date | Time is the last time when this profile was modified | 
| prismaCloudCompute.profileHost.geoip | Unknown | geoip is the list of countries | 


#### Command Example
```!prisma-cloud-compute-profile-host-list hostName=*249* namespace=prod```

#### Human Readable Output

### Apps
|HostId|AppName|StartupProcess|User|LaunchTime|
|---|---|---|---|---|
| host1 | ssh | /usr/sbin/sshd | root | November 10, 2020 09:37:42 AM |
| host1 | docker | /usr/bin/dockerd | root | November 10, 2020 09:37:42 AM |
| host1 | atd | /usr/sbin/atd | root | November 10, 2020 09:37:42 AM |
| host1 | acpid | /usr/sbin/acpid | root | November 10, 2020 09:37:42 AM |
| host1 | cron | /usr/sbin/cron | root | November 10, 2020 09:37:42 AM |
| host1 | apt-daily | /bin/dash | root | November 10, 2020 11:41:34 AM |
| host1 | snapd | /usr/lib/snapd/snapd | root | February 11, 2021 06:23:47 AM |
| host1 | systemd | /lib/systemd/systemd | root | September 02, 2021 10:25:30 AM |
### SSH Events
|HostId|User|Ip|ProcessPath|Command|Time|
|---|---|---|---|---|---|
| host1 | ubuntu | 1.1.1.1 | /usr/bin/clear_console | /usr/bin/clear_console -q | September 02, 2021 11:49:33 AM |
| host1 | ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -alF | September 02, 2021 11:04:01 AM |
| host1 | ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -alF | September 02, 2021 11:03:57 AM |
| host1 | ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -alF | September 02, 2021 11:03:53 AM |
| host1 | ubuntu | 1.1.1.1 | /usr/bin/dircolors | /usr/bin/dircolors | September 02, 2021 11:03:52 AM |
| host1 | ubuntu | 1.1.1.1 | /usr/bin/dirname | dirname /usr/bin/lesspipe | September 02, 2021 11:03:52 AM |
| host1 | ubuntu | 1.1.1.1 | /usr/bin/basename | basename /usr/bin/lesspipe | September 02, 2021 11:03:52 AM |
| host1 | ubuntu | 1.1.1.1 | /bin/dash | /bin/sh /usr/bin/lesspipe | September 02, 2021 11:03:52 AM |
| host1 | ubuntu | 1.1.1.1 | /usr/bin/groups | /usr/bin/groups | September 02, 2021 11:03:52 AM |
| host1 | ubuntu | 1.1.1.1 | /bin/bash | /bin/bash | September 02, 2021 11:03:52 AM |
| host1 | ubuntu | 1.1.1.1 | /bin/su | /bin/su | September 02, 2021 11:03:52 AM |
| host1 | ubuntu | 1.1.1.1 | /usr/bin/sudo | /usr/bin/sudo | September 02, 2021 11:03:52 AM |
| host1 | ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -lt | September 02, 2021 11:03:45 AM |
| host1 | ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -ltr | September 02, 2021 10:27:24 AM |
| host1 | ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -alF | September 02, 2021 10:27:22 AM |
| host1 | ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -alF | September 02, 2021 10:27:20 AM |
| host1 | ubuntu | 1.1.1.1 | /bin/ls | ls /etc/bash_completion.d | September 02, 2021 10:27:18 AM |
| host1 | ubuntu | 1.1.1.1 | /usr/bin/dircolors | /usr/bin/dircolors | September 02, 2021 10:27:18 AM |
| host1 | ubuntu | 1.1.1.1 | /usr/bin/dirname | dirname /usr/bin/lesspipe | September 02, 2021 10:27:18 AM |
| host1 | ubuntu | 1.1.1.1 | /usr/bin/basename | basename /usr/bin/lesspipe | September 02, 2021 10:27:18 AM |
| host1 | ubuntu | 1.1.1.1 | /bin/dash | /bin/sh /usr/bin/lesspipe | September 02, 2021 10:27:18 AM |
| host1 | ubuntu | 1.1.1.1 | /bin/ls | ls /etc/bash_completion.d | September 02, 2021 10:27:18 AM |
| host1 | ubuntu | 1.1.1.1 | /bin/bash | /bin/bash | September 02, 2021 10:27:18 AM |
| host1 | ubuntu | 2.2.2.2 | /usr/bin/scp | /usr/bin/scp | September 02, 2021 10:27:06 AM |
| host1 | ubuntu | 2.2.2.2 | /bin/bash | bash -c scp -t . | September 02, 2021 10:27:06 AM |
| host1 | root | 2.2.2.2 | /bin/sleep | /bin/sleep | September 02, 2021 10:26:52 AM |
| host1 | root | 2.2.2.2 | /bin/bash | bash -c echo 'Please login as the user "ubuntu" rather than the user "root".';echo;sleep 10 | September 02, 2021 10:26:52 AM |
| host1 | root | 1.1.1.1 | /bin/sleep | /bin/sleep | September 02, 2021 10:25:31 AM |
| host1 | root | 1.1.1.1 | /bin/bash | bash -c echo 'Please login as the user "ubuntu" rather than the user "root".';echo;sleep 10 | September 02, 2021 10:25:31 AM |

### prisma-cloud-compute-profile-container-list
***
Get information about the containers and their profile events.


#### Base Command

`prisma-cloud-compute-profile-container-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster | Clusters is the runtime profile k8s cluster filter. | Optional | 
| hostName | Hosts is the runtime profile hostname filter. | Optional | 
| id | IDs is the runtime profile id filter. | Optional | 
| image | Images is the runtime profile image filter. | Optional | 
| imageID | ImageIDs is the runtime profile image id filter. | Optional | 
| namespace | Namespaces is the runtime profile k8s namespace filter. | Optional | 
| os | OS is the service runtime profile OS filter. | Optional | 
| state | States is the runtime profile state filter. | Optional | 
| limit | The maximum number of containers and their profile events. Default is 15. | Optional | 
| offset | The offset number to begin listing containers and their profile events. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| prismaCloudCompute.profileContainer._id | Unknown | Id is the profile ID | 
| prismaCloudCompute.profileContainer.accountsIDs | String | AccountIDs are the cloud account IDs associated with the container runtime profile | 
| prismaCloudCompute.profileContainer.archived | Boolean | Archive indicates whether this profile is archived | 
| prismaCloudCompute.profileContainer.capabilities | Unknown | Capabilities are extended capabilities that are added to the profile based on static analysis | 
| prismaCloudCompute.profileContainer.cluster | String | Cluster is the provided cluster name | 
| prismaCloudCompute.profileContainer.collections | String | Collections are collections to which this profile applies | 
| prismaCloudCompute.profileContainer.created | Date | Created is the profile creation time | 
| prismaCloudCompute.profileContainer.entrypoint | String | Entrypoint is the image entrypoint | 
| prismaCloudCompute.profileContainer.events | Unknown | Events are the last historical interactive process events for this profile, they are updated in a designated flow | 
| prismaCloudCompute.profileContainer.filesystem | Unknown | Filesystem is the profile filesystem metadata | 
| prismaCloudCompute.profileContainer.hash | Unknown | Hash is an uint32 hash associated with the profile | 
| prismaCloudCompute.profileContainer.hostNetwork | Boolean | HostNetwork whether the instance share the network namespace with the host | 
| prismaCloudCompute.profileContainer.hostPid | Boolean | HostPid indicates whether the instance share the pid namespace with the host | 
| prismaCloudCompute.profileContainer.image | Boolean | description | 
| prismaCloudCompute.profileContainer.imageID | String | ImageID is the profile's image ID | 
| prismaCloudCompute.profileContainer.infra | Boolean | InfraContainer indicates this is an infrastructure container | 
| prismaCloudCompute.profileContainer.istio | Boolean | Istio states whether it is an istio-monitored profile | 
| prismaCloudCompute.profileContainer.k8s | Unknown | K8s holds Kubernetes related data | 
| prismaCloudCompute.profileContainer.label | String | Label is the profile's label | 
| prismaCloudCompute.profileContainer.lastUpdate | Date | Modified is the last time when this profile was modified | 
| prismaCloudCompute.profileContainer.learnedStartup | Boolean | LearnedStartup indicates that startup events were learned | 
| prismaCloudCompute.profileContainer.namespace | String | Namespace is the k8s deployment namespace | 
| prismaCloudCompute.profileContainer.network | Unknown | Network is the profile networking metadata | 
| prismaCloudCompute.profileContainer.os | Strubg | OS is the profile image OS | 
| prismaCloudCompute.profileContainer.processes | Unknown | Processes is the profile processes metadata | 
| prismaCloudCompute.profileContainer.relearningCause | String | RelearningCause is a string that describes the reasoning for a profile to enter the learning mode afterbeing activated | 
| prismaCloudCompute.profileContainer.remainingLearningDurationSec | Number | RemainingLearningDurationSec represents the total time left that the system need to finish learning this image | 
| prismaCloudCompute.profileContainer.state | Unknown | State is the current state of the profile. | 


#### Command Example
```!prisma-cloud-compute-profile-container-list id=123 hostName=host1, state=active```

#### Human Readable Output

### Container information
|ContainerID|Image|OS|State|Created|
|---|---|---|---|---|
| 1234 | twistlock/private:console_21_04_439 | Red Hat Enterprise Linux 8.4 (Ootpa) | active | September 02, 2021 11:05:08 AM |
### Containers processes
|ContainerID|Type|Path|DetectionTime|
|---|---|---|---|
| 1234 | static | /usr/bin/mongodump | January 01, 0001 00:00:00 AM |
| 1234 | static | /usr/bin/mongorestore | January 01, 0001 00:00:00 AM |
| 1234 | static | /usr/bin/rpm | January 01, 0001 00:00:00 AM |
| 1234 | static | /usr/bin/gpgconf | January 01, 0001 00:00:00 AM |
| 1234 | static | /usr/bin/gpg-connect-agent | January 01, 0001 00:00:00 AM |
| 1234 | static | /usr/bin/apt-get | January 01, 0001 00:00:00 AM |
| 1234 | static | /usr/bin/apt-config | January 01, 0001 00:00:00 AM |
| 1234 | static | /usr/bin/touch | January 01, 0001 00:00:00 AM |
| 1234 | static | /usr/bin/dpkg | January 01, 0001 00:00:00 AM |
| 1234 | static | /usr/bin/cmp | January 01, 0001 00:00:00 AM |
| 1234 | static | /bin/cat | January 01, 0001 00:00:00 AM |
| 1234 | static | /bin/rm | January 01, 0001 00:00:00 AM |
| 1234 | static | /bin/readlink | January 01, 0001 00:00:00 AM |
| 1234 | static | /bin/sed | January 01, 0001 00:00:00 AM |
| 1234 | static | /bin/cp | January 01, 0001 00:00:00 AM |
| 1234 | static | /bin/mktemp | January 01, 0001 00:00:00 AM |
| 1234 | static | /bin/chmod | January 01, 0001 00:00:00 AM |
| 1234 | static | /usr/bin/sort | January 01, 0001 00:00:00 AM |
| 1234 | static | /usr/bin/test | January 01, 0001 00:00:00 AM |
| 1234 | static | /usr/bin/find | January 01, 0001 00:00:00 AM |
| 1234 | static | /usr/bin/gpgv | January 01, 0001 00:00:00 AM |
| 1234 | static | /usr/bin/dirname | January 01, 0001 00:00:00 AM |
| 1234 | static | /bin/sh | January 01, 0001 00:00:00 AM |
| 1234 | static | /bin/echo | January 01, 0001 00:00:00 AM |
| 1234 | static | /usr/bin/tar | January 01, 0001 00:00:00 AM |
| 1234 | static | /usr/bin/sed | January 01, 0001 00:00:00 AM |
| 1234 | static | /app/server | January 01, 0001 00:00:00 AM |
| 1234 | behavioral | /usr/bin/mongod | September 02, 2021 11:05:08 AM |
### prisma-cloud-compute-profile-container-hosts-list
***
Get the hosts where a specific container is running.


#### Base Command

`prisma-cloud-compute-profile-container-hosts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Container profile ID. | Required | 
| cluster | Clusters is the runtime profile k8s cluster filter. | Optional | 
| hostName | Hosts is the runtime profile hostname filter. | Optional | 
| image | Images is the runtime profile image filter. | Optional | 
| imageID | ImageIDs is the runtime profile image id filter. | Optional | 
| namespace | Namespaces is the runtime profile k8s namespace filter. | Optional | 
| os | OS is the service runtime profile OS filter. | Optional | 
| state | States is the runtime profile state filter. | Optional | 
| limit | The maximum number of hosts to return. Default is 50. Default is 50. | Optional | 
| offset | The offset number to begin listing hosts of the container. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| prismaCloudCompute.profileContainerHost.ContainerID | String | Container ID | 
| prismaCloudCompute.profileContainerHost.HostsIDs | Unknown | The container's host IDs. | 

#### Command Example
```!prisma-cloud-compute-profile-container-hosts-list id=123```

#### Human Readable Output
### Containers hosts list
|ContainerID|HostsIDs|
|---|---|
| container_id_1 | host_id-1,<br>host_id-2 |


### prisma-cloud-compute-profile-container-forensic-list
***
Get runtime forensics data for a specific container on a specific host


#### Base Command

`prisma-cloud-compute-profile-container-forensic-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The container ID. | Required | 
| collections | Collections are collections scoping the query. | Optional | 
| hostname | Hostname is the hostname for which data should be fetched. | Required | 
| incidentID | IncidentID is the incident ID in case the request kind is an incident. | Optional | 
| eventTime | EventTime is the forensic event pivot time in milliseconds (used to fetch events). | Optional | 
| format | Format is the forensic data format. | Optional | 
| limit | maximum of forensics data records to return. Default is 20. | Optional | 
| offset | The offset number to begin listing records from . Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| prismaCloudCompute.containerForensic.Forensics.allPorts | Boolean | AllPorts indicates all listening ports are allowed | 
| prismaCloudCompute.containerForensic.Forensics.attack | Unknown | Attack is the event attack type. | 
| prismaCloudCompute.containerForensic.Forensics.category | Unknown | Category is the incident category. | 
| prismaCloudCompute.containerForensic.Forensics.command | String | Command is the event command | 
| prismaCloudCompute.containerForensic.Forensics.containerId | Unknown | ContainerID is the event container id | 
| prismaCloudCompute.containerForensic.Forensics.dstIP | String | DstIP is the destination IP of the connection | 
| prismaCloudCompute.containerForensic.Forensics.dstPort | Unknown | DstPort is the destination port | 
| prismaCloudCompute.containerForensic.Forensics.dstProfileID | String | DstProfileID is the profile ID of the connection destination | 
| prismaCloudCompute.containerForensic.Forensics.effect | String | Effect is the runtime audit effect | 
| prismaCloudCompute.containerForensic.Forensics.listeningStartTime | Date | listeningStartTime is the port listening start time | 
| prismaCloudCompute.containerForensic.Forensics.message | String | Message is the runtime audit message | 
| prismaCloudCompute.containerForensic.Forensics.networkCollectionType | Unknown | NetworkCollectionType is the type of the network collection method | 
| prismaCloudCompute.containerForensic.Forensics.outbound | Boolean | Outbound indicates if the port is outbound | 
| prismaCloudCompute.containerForensic.Forensics.path | String | Path is the event path | 
| prismaCloudCompute.containerForensic.Forensics.pid | Number | Pid is the event process id | 
| prismaCloudCompute.containerForensic.Forensics.port | Number | Port is the listening port | 
| prismaCloudCompute.containerForensic.Forensics.ppid | Number | PPid is the event parent process id | 
| prismaCloudCompute.containerForensic.Forensics.process | String | Process is the event processdescription | 
| prismaCloudCompute.containerForensic.Forensics.srcIP | String | SrcIP is the source IP of the connection | 
| prismaCloudCompute.containerForensic.Forensics.srcProfileID | String | SrcProfileID is the profile ID of the connection source | 
| prismaCloudCompute.containerForensic.Forensics.static | Boolean | Static indicates the event was added to the profile without behavioral indication | 
| prismaCloudCompute.containerForensic.Forensics.type | Unknown | Type is the event type. | 
| prismaCloudCompute.containerForensic.Forensics.timestamp | Boolean | Timestamp is the event timestamp | 
| prismaCloudCompute.containerForensic.Forensics.user | String | User is the event user | 
| prismaCloudCompute.containerForensic.ContainerID | String | Container ID of the forensic. | 


#### Command Example
```!prisma-cloud-compute-profile-container-forensic-list id=123,456 hostname=hostname1```

#### Human Readable Output
### Containers forensic report
|ContainerID|Type|Path|
|---|---|---|
| 123 | Process spawned | /usr/local/bin/defender |
| 123 | Process spawned | /usr/local/bin/defender |
| 123 | Process spawned | /bin/sed |
| 123 | Binary created | /tmp/compute_security_updates275686626/usr/lib/apt/solvers/dump |
| 123 | Binary created | /tmp/compute_security_updates275686626/usr/lib/apt/solvers/apt |
| 123 | Binary created | /tmp/compute_security_updates275686626/usr/lib/apt/methods/store |
| 123 | Binary created | /tmp/compute_security_updates275686626/usr/lib/apt/methods/rsh |
| 123 | Binary created | /tmp/compute_security_updates275686626/usr/lib/apt/methods/rred |
| 123 | Binary created | /tmp/compute_security_updates275686626/usr/lib/apt/methods/mirror |
| 123 | Binary created | /tmp/compute_security_updates275686626/usr/lib/apt/methods/https |
| 123 | Binary created | /tmp/compute_security_updates275686626/usr/lib/apt/methods/http |
| 123 | Binary created | /tmp/compute_security_updates275686626/usr/lib/apt/methods/gpgv |
| 123 | Binary created | /tmp/compute_security_updates275686626/usr/lib/apt/methods/ftp |
| 123 | Binary created | /tmp/compute_security_updates275686626/usr/lib/apt/methods/file |
| 123 | Binary created | /tmp/compute_security_updates275686626/usr/lib/apt/methods/copy |
| 123 | Binary created | /tmp/compute_security_updates275686626/usr/lib/apt/methods/cdrom |
| 123 | Binary created | /tmp/compute_security_updates275686626/usr/lib/apt/apt-helper |
| 123 | Process spawned | /usr/local/bin/defender |
| 123 | Process spawned | /usr/local/bin/defender |
| 123 | Process spawned | /usr/local/bin/defender |
