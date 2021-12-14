Prisma™ Cloud Compute Edition delivers cloud workload protection (CWPP) for modern
enterprises, providing holistic protection across hosts, containers, and serverless deployments in any cloud, 
throughout the application lifecycle. Prisma Cloud Compute Edition is cloud native and API-enabled, 
protecting all your workloads regardless of their underlying compute technology or the cloud in which they run.

This integration lets you import **Palo Alto Networks - Prisma Cloud Compute** alerts into Cortex XSOAR

## Configure Prisma Cloud Compute to Send Alerts to Cortex XSOAR

To send alerts from Prisma Cloud Compute to Cortex XSOAR, you need to create an alert profile.

1. Log in to your Prisma Cloud Compute console.
2. Navigate to **Manage > Alerts**.
3. Click **Add Profile** to create a new alert profile.
4. On the left, select **Demisto** from the provider list.
5. On the right, select the alert triggers. Alert triggers specify which alerts are sent to Cortex XSOAR.
6. Click **Save** to save the alert profile.

## Configure Prisma Cloud Compute on Cortex XSOAR

1. Navigate to **Settings > Integrations > Servers & Services**.
2. Search for **Prisma Cloud Compute**.
3. Click **Add instance** to create and configure a new integration.
   
   | Parameter | Description | Example |
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


Commands
--------

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

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
| PrismaCloudCompute.ProfileHost._id | String | ID is the profile ID \(hostname\) | 
| PrismaCloudCompute.ProfileHost.accountID | String | AccountID is the cloud account ID associated with the profile | 
| PrismaCloudCompute.ProfileHost.apps.listeningPorts.command | String | Command represents the command that triggered the connection | 
| PrismaCloudCompute.ProfileHost.apps.listeningPorts.modified | Date | Modified is a timestamp of when the event occurred | 
| PrismaCloudCompute.ProfileHost.apps.listeningPorts.port | Number | Port is the listening port number | 
| PrismaCloudCompute.ProfileHost.apps.listeningPorts.processPath | String | ProcessPath represents the path to the process that uses the port | 
| PrismaCloudCompute.ProfileHost.apps.name | String | Name is the app name | 
| PrismaCloudCompute.ProfileHost.apps.outgoingPorts.command | String | Command represents the command that triggered the connection | 
| PrismaCloudCompute.ProfileHost.apps.outgoingPorts.country | String | Country is the country ISO code for the given IP address | 
| PrismaCloudCompute.ProfileHost.apps.outgoingPorts.ip | String | IP is the IP address captured over this port | 
| PrismaCloudCompute.ProfileHost.apps.outgoingPorts.modified | Date | Modified is a timestamp of when the event occurred | 
| PrismaCloudCompute.ProfileHost.apps.outgoingPorts.port | Number | Port is the outgoing port number | 
| PrismaCloudCompute.ProfileHost.apps.outgoingPorts.processPath | String | ProcessPath represents the path to the process that uses the port | 
| PrismaCloudCompute.ProfileHost.apps.processes.command | String | Command is the executed command | 
| PrismaCloudCompute.ProfileHost.apps.processes.md5 | String | MD5 is the process binary MD5 sum | 
| PrismaCloudCompute.ProfileHost.apps.processes.modified | Boolean | Modified indicates if the process binary was modified after the container has started | 
| PrismaCloudCompute.ProfileHost.apps.processes.path | String | Path is the process binary path | 
| PrismaCloudCompute.ProfileHost.apps.processes.ppath | String | PPath is the parent process path | 
| PrismaCloudCompute.ProfileHost.apps.processes.time | Date | Time is the time in which the process was added. If the process was modified, Time is the modification time | 
| PrismaCloudCompute.ProfileHost.apps.processes.user | String | User represents the username that started the process | 
| PrismaCloudCompute.ProfileHost.apps.startupProcess.command | String | Command is the executed command | 
| PrismaCloudCompute.ProfileHost.apps.startupProcess.md5 | String | MD5 is the process binary MD5 sum | 
| PrismaCloudCompute.ProfileHost.apps.startupProcess.modified | Boolean | Modified indicates if the process binary was modified after the container has started | 
| PrismaCloudCompute.ProfileHost.apps.startupProcess.path | String | Path is the process binary path | 
| PrismaCloudCompute.ProfileHost.apps.startupProcess.ppath | String | PPath is the parent process path | 
| PrismaCloudCompute.ProfileHost.apps.startupProcess.time | Date | Time is the time in which the process was added. If the process was modified, Time is the modification time | 
| PrismaCloudCompute.ProfileHost.apps.startupProcess.user | String | User represents the username that started the process | 
| PrismaCloudCompute.ProfileHost.collections | String | Collections is a list of collections to which this profile applies | 
| PrismaCloudCompute.ProfileHost.created | Date | Created is the profile creation time | 
| PrismaCloudCompute.ProfileHost.hash | Number | Hash is an uint32 hash associated with the profile | 
| PrismaCloudCompute.ProfileHost.labels | String | Labels are the labels associated with the profile | 
| PrismaCloudCompute.ProfileHost.sshEvents.command | String | Command is the executed command | 
| PrismaCloudCompute.ProfileHost.sshEvents.country | String | Country represents the SSH client's origin country | 
| PrismaCloudCompute.ProfileHost.sshEvents.ip | String | IP address represents the connection client IP address | 
| PrismaCloudCompute.ProfileHost.sshEvents.loginTime | Date | LoginTime represents the SSH login time | 
| PrismaCloudCompute.ProfileHost.sshEvents.md5 | String | MD5 is the process binary MD5 sum | 
| PrismaCloudCompute.ProfileHost.sshEvents.modified | Boolean | Modified indicates if the process binary was modified after the container has started | 
| PrismaCloudCompute.ProfileHost.sshEvents.path | String | Path is the process binary path | 
| PrismaCloudCompute.ProfileHost.sshEvents.ppath | String | PPath is the parent process path | 
| PrismaCloudCompute.ProfileHost.sshEvents.time | Date | Time is the time in which the process was added. If the process was modified, Time is the modification time | 
| PrismaCloudCompute.ProfileHost.sshEvents.user | String | User represents the username that started the process | 
| PrismaCloudCompute.ProfileHost.time | Date | Time is the last time when this profile was modified | 
| PrismaCloudCompute.ProfileHost.geoip.countries.code | String | Code is the country code origin of a that computer accessed the host | 
| PrismaCloudCompute.ProfileHost.geoip.countries.ip | String | IP is the ip origin of a computer that acccesed the host | 
| PrismaCloudCompute.ProfileHost.geoip.countries.modified | Date | Modified indiciates whether the computer origin that accessed the host has been changed | 
| PrismaCloudCompute.ProfileHost.geoip.modified | Date | Modified indicates whether there was a change in the list of geoip countries | 


#### Command Example
```!prisma-cloud-compute-profile-host-list hostname=*163*```

#### Context Example
```json
{
    "PrismaCloudCompute": {
        "ProfileHost": {
            "hash": 1, 
            "created": "2020-11-10T09:37:30.314Z", 
            "geoip": {
                "modified": "2021-12-10T11:06:03.206Z", 
                "countries": [
                    {
                        "ip": "1.1.1.1", 
                        "code": "US", 
                        "modified": "2021-12-10T11:06:03.206Z"
                    }, 
                    {
                        "ip": "2.2.2.2", 
                        "code": "IE", 
                        "modified": "2021-12-10T05:22:01.858Z"
                    }
                ]
            }, 
            "labels": [
                "osDistro:amzn", 
                "osVersion:2"
            ], 
            "apps": [
                {
                    "processes": [
                        {
                            "ppath": "/usr/lib/systemd/systemd", 
                            "command": "/usr/sbin/auditd", 
                            "user": "root", 
                            "time": "2020-11-10T09:37:30.415Z", 
                            "path": "/usr/sbin/auditd", 
                            "md5": ""
                        }
                    ], 
                    "startupProcess": {
                        "ppath": "/usr/lib/systemd/systemd", 
                        "command": "/usr/sbin/auditd", 
                        "user": "root", 
                        "time": "2020-11-10T09:37:30.415Z", 
                        "path": "/usr/sbin/auditd", 
                        "md5": ""
                    }, 
                    "name": "auditd"
                }, 
                {
                    "processes": [
                        {
                            "ppath": "/usr/lib/systemd/systemd", 
                            "command": "/usr/sbin/atd -f", 
                            "user": "root", 
                            "time": "2020-11-10T09:37:30.415Z", 
                            "path": "/usr/sbin/atd", 
                            "md5": ""
                        }
                    ], 
                    "startupProcess": {
                        "ppath": "/usr/lib/systemd/systemd", 
                        "command": "/usr/sbin/atd -f", 
                        "user": "root", 
                        "time": "2020-11-10T09:37:30.415Z", 
                        "path": "/usr/sbin/atd", 
                        "md5": ""
                    }, 
                    "name": "atd"
                }
            ], 
            "collections": [
                "All", 
                "676921422616"
            ], 
            "time": "2021-12-10T11:06:03.206Z", 
            "sshEvents": [
                {
                    "ppath": "/usr/bin/bash", 
                    "country": "IL", 
                    "time": "December 10, 2021 11:06:03 AM", 
                    "command": "grep twistlock_data - High rate of events, throttling started", 
                    "user": "user123", 
                    "ip": "1.2.3.4", 
                    "path": "/usr/bin/grep", 
                    "loginTime": "September 02, 2021 09:27:41 AM", 
                    "md5": ""
                },
               {
                  "ppath": "/usr/bin/bash",
                  "country": "IL",
                  "time": "December 10, 2021 11:06:03 AM",
                  "command": "docker -H unix:///var/run/docker.sock ps -a --format {{ .Names }}",
                  "user": "user123",
                  "ip": "1.1.1.1",
                  "path": "/usr/bin/docker",
                  "loginTime": "September 02, 2021 09:27:41 AM",
                  "md5": ""
               }
            ], 
            "_id": "host163", 
            "accountID": "1234"
        }
    }
}
```

#### Human Readable Output - One Host
### Host Description
|Hostname|Distribution|Collections|
|---|---|---|
| host163 | amzn 2 | All,<br>676921422616 |
### Apps
|AppName|StartupProcess|User|LaunchTime|
|---|---|---|---|
| auditd | /usr/sbin/auditd | root | November 10, 2020 09:37:30 AM |
| atd | /usr/sbin/atd | root | November 10, 2020 09:37:30 AM |
### SSH Events
|User|Ip|ProcessPath|Command|Time|
|---|---|---|---|---|
| user123 | 1.2.3.4 | /usr/bin/grep | grep twistlock_data - High rate of events, throttling started | December 10, 2021 11:06:03 AM |
| user123 | 1.1.1.1 | /usr/bin/docker | docker -H unix:///var/run/docker.sock ps -a --format {{ .Names }} | December 10, 2021 11:06:03 AM |

#### Human Readable Output - Multiple Hosts
### Host Description
|Hostname|Distribution|Collections|
|---|---|---|
| host163 | amzn 2 | All,<br>676921422616 |
| host249 | Ubuntu 16.04 | All,<br>676921422616 |



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
| PrismaCloudCompute.ProfileContainer._id | String | Id is the profile ID | 
| PrismaCloudCompute.ProfileContainer.accountsIDs | String | AccountIDs are the cloud account IDs associated with the container runtime profile | 
| PrismaCloudCompute.ProfileContainer.archived | Boolean | Archive indicates whether this profile is archived | 
| PrismaCloudCompute.ProfileContainer.capabilities.ci | Boolean | CI indicates if the container allowed to write binaries to disk and run them based on static analysis | 
| PrismaCloudCompute.ProfileContainer.capabilities.cloudMetadata | Boolean | CloudMetadata indicates the given container can query cloud metadata api based on static analysis | 
| PrismaCloudCompute.ProfileContainer.capabilities.dnsCache | Boolean | DNSCache are DNS services that are used by all the pods in the cluster | 
| PrismaCloudCompute.ProfileContainer.capabilities.dynamicDNSQuery | Boolean | DynamicDNSQuery indicates capped behavioral dns queries | 
| PrismaCloudCompute.ProfileContainer.capabilities.dynamicFileCreation | Boolean | DynamicFileCreation indicates capped behavioral filesystem paths | 
| PrismaCloudCompute.ProfileContainer.capabilities.dynamicProcessCreation | Boolean | DynamicProcessCreation indicates capped behavioral processes | 
| PrismaCloudCompute.ProfileContainer.capabilities.k8s | Boolean | Kubernetes indicates the given container can perform k8s networking tasks \(e.g., contact to api server\) | 
| PrismaCloudCompute.ProfileContainer.capabilities.proxy | Boolean | Proxy indicates the container can listen on any port and perform multiple outbound connection | 
| PrismaCloudCompute.ProfileContainer.capabilities.sshd | Boolean | Sshd indicates whether the container can run sshd process | 
| PrismaCloudCompute.ProfileContainer.capabilities.unpacker | Boolean | Unpacker indicates the container is allowed to write shared libraries to disk | 
| PrismaCloudCompute.ProfileContainer.cluster | String | Cluster is the provided cluster name | 
| PrismaCloudCompute.ProfileContainer.collections | String | Collections are collections to which this profile applies | 
| PrismaCloudCompute.ProfileContainer.created | Date | Created is the profile creation time | 
| PrismaCloudCompute.ProfileContainer.entrypoint | String | Entrypoint is the image entrypoint | 
| PrismaCloudCompute.ProfileContainer.events._id | String | ID is the history event entity | 
| PrismaCloudCompute.ProfileContainer.events.command | String | Command is the process that was executed | 
| PrismaCloudCompute.ProfileContainer.events.hostname | String | Hostname is the hostname on which the command was invoked | 
| PrismaCloudCompute.ProfileContainer.events.time | Date | Time is the time of the event | 
| PrismaCloudCompute.ProfileContainer.filesystem.behavioral.mount | Boolean | Mount indicates whether the given folder is a mounted | 
| PrismaCloudCompute.ProfileContainer.filesystem.behavioral.path | String | Path is the file path | 
| PrismaCloudCompute.ProfileContainer.filesystem.behavioral.process | String | Process is the process that accessed the file | 
| PrismaCloudCompute.ProfileContainer.filesystem.behavioral.time | Date | Time is the time in which the file was added | 
| PrismaCloudCompute.ProfileContainer.filesystem.static.mount | Boolean | Mount indicates whether the given folder is a mounted | 
| PrismaCloudCompute.ProfileContainer.filesystem.static.path | String | Path is the file path | 
| PrismaCloudCompute.ProfileContainer.filesystem.static.process | String | Process is the process that accessed the file | 
| PrismaCloudCompute.ProfileContainer.filesystem.static.time | Date | Time is the time in which the file was added | 
| PrismaCloudCompute.ProfileContainer.hash | Number | Hash is an uint32 hash associated with the profile | 
| PrismaCloudCompute.ProfileContainer.hostNetwork | Boolean | HostNetwork whether the instance share the network namespace with the host | 
| PrismaCloudCompute.ProfileContainer.hostPid | Boolean | HostPid indicates whether the instance share the pid namespace with the host | 
| PrismaCloudCompute.ProfileContainer.image | String | Image is the image that the container runs with | 
| PrismaCloudCompute.ProfileContainer.imageID | String | ImageID is the profile's image ID | 
| PrismaCloudCompute.ProfileContainer.infra | Boolean | InfraContainer indicates this is an infrastructure container | 
| PrismaCloudCompute.ProfileContainer.istio | Boolean | Istio states whether it is an istio-monitored profile | 
| PrismaCloudCompute.ProfileContainer.k8s.clusterRoles.labels.key | String | Key is the key of the label | 
| PrismaCloudCompute.ProfileContainer.k8s.clusterRoles.labels.value | String | Value is the value of the label | 
| PrismaCloudCompute.ProfileContainer.k8s.clusterRoles.name | String | Name is the role name | 
| PrismaCloudCompute.ProfileContainer.k8s.clusterRoles.roleBinding | String | RoleBinding is the name of the role binding used for display | 
| PrismaCloudCompute.ProfileContainer.k8s.clusterRoles.rules | String | Rules are the list of rules associated with the cluster role | 
| PrismaCloudCompute.ProfileContainer.k8s.roles.labels.key | String | Key is the key of the label | 
| PrismaCloudCompute.ProfileContainer.k8s.roles.labels.value | String | Value is the value of the label | 
| PrismaCloudCompute.ProfileContainer.k8s.roles.name | String | Name is the kubernetes role name | 
| PrismaCloudCompute.ProfileContainer.k8s.roles.namespace | String | Namespace is the namespace associated with the role | 
| PrismaCloudCompute.ProfileContainer.k8s.roles.roleBinding | String | RoleBinding is the name of the role binding used for display | 
| PrismaCloudCompute.ProfileContainer.k8s.roles.rules | String | Rules are the policy rules associated with the role | 
| PrismaCloudCompute.ProfileContainer.k8s.serviceAccount | String | ServiceAccount is the service account used to access Kubernetes apiserverThis field will be empty if the container is not running inside of a Pod | 
| PrismaCloudCompute.ProfileContainer.label | String | Label is the profile's label | 
| PrismaCloudCompute.ProfileContainer.lastUpdate | Date | Modified is the last time when this profile was modified | 
| PrismaCloudCompute.ProfileContainer.learnedStartup | Boolean | LearnedStartup indicates that startup events were learned | 
| PrismaCloudCompute.ProfileContainer.namespace | String | Namespace is the k8s deployment namespace | 
| PrismaCloudCompute.ProfileContainer.network.behavioral.dnsQueries.domainName | String | DomainName is the queried domain name | 
| PrismaCloudCompute.ProfileContainer.network.behavioral.dnsQueries.domainType | String | DomainType is the queried domain type | 
| PrismaCloudCompute.ProfileContainer.network.listeningPorts.app | String | App is the name of the app | 
| PrismaCloudCompute.ProfileContainer.network.listeningPorts.portsData.all | Boolean | All indicates that this port data represents any arbitrary ports | 
| PrismaCloudCompute.ProfileContainer.network.listeningPorts.portsData.ports.port | Number | Port is the port number | 
| PrismaCloudCompute.ProfileContainer.network.listeningPorts.portsData.ports.time | Date | Time is the learning timestamp of this port | 
| PrismaCloudCompute.ProfileContainer.network.outboundPorts.portsData.all | Boolean | All indicates that this port data represents any arbitrary ports | 
| PrismaCloudCompute.ProfileContainer.network.outboundPorts.portsData.ports.port | Number | Port is the port number | 
| PrismaCloudCompute.ProfileContainer.network.static.listeningPorts.ports.time | Date | Time is the learning timestamp of this port | 
| PrismaCloudCompute.ProfileContainer.network.static.listeningPorts.app | String | App is the name of the app | 
| PrismaCloudCompute.ProfileContainer.network.static.listeningPorts.portsData.all | Boolean | All indicates that this port data represents any arbitrary ports | 
| PrismaCloudCompute.ProfileContainer.network.static.listeningPorts.portsData.ports.port | Number | Port is the port number | 
| PrismaCloudCompute.ProfileContainer.network.static.listeningPorts.portsData.ports.time | Date | Time is the learning timestamp of this port | 
| PrismaCloudCompute.ProfileContainer.os | String | OS is the profile image OS | 
| PrismaCloudCompute.ProfileContainer.processes.behavioral.command | String | Command is the executed command | 
| PrismaCloudCompute.ProfileContainer.processes.behavioral.md5 | String | MD5 is the process binary MD5 sum | 
| PrismaCloudCompute.ProfileContainer.processes.behavioral.modified | Boolean | Modified indicates if the process binary was modified after the container has started | 
| PrismaCloudCompute.ProfileContainer.processes.behavioral.path | String | Path is the process binary path | 
| PrismaCloudCompute.ProfileContainer.processes.behavioral.ppath | String | PPath is the parent process path | 
| PrismaCloudCompute.ProfileContainer.processes.behavioral.time | Date | Time is the time in which the process was added. If the process was modified, Time is the modification time | 
| PrismaCloudCompute.ProfileContainer.processes.behavioral.user | String | User represents the username that started the process | 
| PrismaCloudCompute.ProfileContainer.processes.static.command | String | Command is the executed command | 
| PrismaCloudCompute.ProfileContainer.processes.static.md5 | String | MD5 is the process binary MD5 sum | 
| PrismaCloudCompute.ProfileContainer.processes.static.modified | Boolean | Modified indicates if the process binary was modified after the container has started | 
| PrismaCloudCompute.ProfileContainer.processes.static.path | String | Path is the process binary path | 
| PrismaCloudCompute.ProfileContainer.processes.static.ppath | String | PPath is the parent process path | 
| PrismaCloudCompute.ProfileContainer.processes.static.time | Date | Time is the time in which the process was added. If the process was modified, Time is the modification time | 
| PrismaCloudCompute.ProfileContainer.processes.static.user | String | User represents the username that started the process | 
| PrismaCloudCompute.ProfileContainer.relearningCause | String | RelearningCause is a string that describes the reasoning for a profile to enter the learning mode afterbeing activated | 
| PrismaCloudCompute.ProfileContainer.remainingLearningDurationSec | Number | RemainingLearningDurationSec represents the total time left that the system need to finish learning this image | 
| PrismaCloudCompute.ProfileContainer.state | String | State is the current state of the profile. | 


#### Command Example
```!prisma-cloud-compute-profile-container-list image=*defender* limit=1```

#### Context Example
```json
{
    "PrismaCloudCompute": {
        "ProfileContainer": {
            "image": "twistlock/private:defender_21_04_439", 
            "hostNetwork": true, 
            "learnedStartup": true, 
            "k8s": {}, 
            "archived": false, 
            "network": {
                "geoip": {
                    "modified": "2021-12-10T13:31:42.924Z", 
                    "countries": [
                        {
                            "ip": "1.1.1.1", 
                            "code": "IE", 
                            "modified": "2021-12-10T13:31:42.922Z"
                        },
                        {
                            "ip": "2.2.2.2", 
                            "code": "US", 
                            "modified": "2021-12-09T13:30:42.148Z"
                        }
                    ]
                }, 
                "static": {
                    "listeningPorts": []
                }, 
                "behavioral": {
                    "outboundPorts": {
                        "ports": [
                            {
                                "port": 80, 
                                "time": "2021-09-02T11:05:16.836Z"
                            }
                        ]
                    }
                }
            }, 
            "capabilities": {
                "ci": true
            }, 
            "label": "twistlock", 
            "state": "active", 
            "collections": [
                "All", 
                "676921422616", 
                "Prisma Cloud resources"
            ], 
            "entrypoint": "/usr/local/bin/defender", 
            "events": null, 
            "lastUpdate": "2021-09-02T11:05:10.935Z", 
            "hash": 3, 
            "infra": false, 
            "accountIDs": [
                "676921422616"
            ], 
            "processes": {
                "static": [
                    {
                        "ppath": "", 
                        "path": "/usr/bin/mongodump", 
                        "time": "0001-01-01T00:00:00Z", 
                        "md5": ""
                    }, 
                    {
                        "ppath": "", 
                        "path": "/usr/bin/mongorestore", 
                        "time": "0001-01-01T00:00:00Z", 
                        "md5": ""
                    }
                ], 
                "behavioral": [
                    {
                        "ppath": "/usr/local/bin/defender", 
                        "path": "/usr/local/bin/fsmon", 
                        "time": "2021-09-02T11:05:08.931Z", 
                        "md5": ""
                    }, 
                    {
                        "ppath": "/usr/bin/apt-get", 
                        "path": "/usr/lib/apt/methods/gpgv", 
                        "time": "2021-11-24T15:12:28.502Z", 
                        "command": "gpgv", 
                        "md5": ""
                    }
                ]
            }, 
            "created": "2020-09-02T11:05:08.931Z", 
            "imageID": "sha256:8d82e2c21c33e1ffb37ea901d18df15c08123258609e6d7c4aecc7fb4a5a8738", 
            "filesystem": {
                "static": [
                    {
                        "process": "*", 
                        "path": "/var/log/audit", 
                        "mount": true, 
                        "time": "2021-09-02T11:05:08.931Z"
                    }, 
                    {
                        "process": "*", 
                        "path": "/var/lib/twistlock", 
                        "mount": true, 
                        "time": "2021-09-02T11:05:08.931Z"
                    }
                ], 
                "behavioral": [
                    {
                        "process": "/usr/local/bin/defender", 
                        "path": "/prisma-static-data", 
                        "mount": true, 
                        "time": "2021-09-02T11:05:10.935Z"
                    }, 
                    {
                        "process": "/usr/local/bin/defender", 
                        "path": "/tmp", 
                        "mount": false, 
                        "time": "2021-09-02T11:05:16.784Z"
                    }
                ]
            }, 
            "_id": "container123", 
            "os": "Red Hat Enterprise Linux 8.4 (Ootpa)", 
            "remainingLearningDurationSec": -1, 
            "hostPid": true
        }
    }
}
```

#### Human Readable Output - One Container
### Container Description
|ContainerID|Image|Os|State|Created|EntryPoint|
|---|---|---|---|---|---|
| container123 | twistlock/private:defender_21_04_439 | Red Hat Enterprise Linux 8.4 (Ootpa) | active | September 02, 2020 11:05:08 AM | /usr/local/bin/defender |
### Processes
|Type|Path|DetectionTime|Md5|
|---|---|---|---|
| static | /usr/bin/mongodump | January 01, 2021 00:00:00 AM |  |
| static | /usr/bin/mongorestore | January 01, 2021 00:00:00 AM |  |
| behavioral | /usr/local/bin/fsmon | September 02, 2021 11:05:08 AM |  |
| behavioral | /usr/lib/apt/methods/gpgv | November 24, 2021 15:12:28 PM |  |

#### Human Readable Output - Multiple Containers
### Container Description
|ContainerID|Image|Os|State|Created|EntryPoint|
|---|---|---|---|---|---|
| container123 | twistlock/private:defender_21_04_439 | Red Hat Enterprise Linux 8.4 (Ootpa) | active | September 02, 2021 11:05:08 AM | /usr/local/bin/defender |
| container1234 | twistlock/private:console_21_04_439 | Red Hat Enterprise Linux 8.4 (Ootpa) | active | September 02, 2021 11:05:08 AM | /app/server |

### prisma-cloud-compute-profile-container-hosts-list
***
Get the hosts where a specific container is running.


#### Base Command

`prisma-cloud-compute-profile-container-hosts-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Container profile ID, can be retrieved from prisma-cloud-compute-profile-container-list command. | Required | 
| limit | The maximum number of hosts to return, must be between 1-50. Default is 50. | Optional | 
| offset | The offset number to begin listing hosts of the container. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.ProfileContainerHost.containerID | String | The container ID | 
| PrismaCloudCompute.ProfileContainerHost.hostsIDs | String | The list of hosts where this container is running. | 


#### Command Example
```!prisma-cloud-compute-profile-container-hosts-list id=container123```
!prisma-cloud-compute-profile-container-hosts-list id=sha256%3A8d82e2c21c33e1ffb37ea901d18df15c08123258609e6d7c4aecc7fb4a5a8738_twistlock_
#### Context Example
```json
{
    "PrismaCloudCompute": {
        "ProfileContainerHost": {
            "containerID": "container123", 
            "hostsIDs": [
                "host1", 
                "host2"
            ]
        }
    }
}
```

#### Human Readable Output
### Hosts
|HostsIDs|
|---|
| ip-172-31-5-163.eu-west-1.compute.internal,<br>ip-172-31-23-249.eu-west-1.compute.internal |

### prisma-cloud-compute-profile-container-forensic-list
***
Get runtime forensics data for a specific container on a specific host


#### Base Command

`prisma-cloud-compute-profile-container-forensic-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The container ID, can be retrieved from prisma-cloud-compute-profile-container-list command. | Required | 
| collections | Collections are collections scoping the query. | Optional | 
| hostname | Hostname is the hostname for which data should be fetched. | Required | 
| incident_id | IncidentID is the incident ID in case the request kind is an incident. | Optional | 
| limit | maximum of forensics data records to return, must be between 1-50. Default is 20. | Optional | 
| offset | The offset number to begin listing records from. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.ContainerForensic.containerID | String | The container ID. | 
| PrismaCloudCompute.ContainerForensic.hostname | String | The hostname. | 
| PrismaCloudCompute.ContainerForensic.Forensics.allPorts | Boolean | AllPorts indicates all listening ports are allowed | 
| PrismaCloudCompute.ContainerForensic.Forensics.attack | String | Attack is the event attack type. | 
| PrismaCloudCompute.ContainerForensic.Forensics.category | String | Category is the incident category. | 
| PrismaCloudCompute.ContainerForensic.Forensics.command | String | Command is the event command | 
| PrismaCloudCompute.ContainerForensic.Forensics.containerId | String | ContainerID is the event container id | 
| PrismaCloudCompute.ContainerForensic.Forensics.dstIP | String | DstIP is the destination IP of the connection | 
| PrismaCloudCompute.ContainerForensic.Forensics.dstPort | String | DstPort is the destination port | 
| PrismaCloudCompute.ContainerForensic.Forensics.dstProfileID | String | DstProfileID is the profile ID of the connection destination | 
| PrismaCloudCompute.ContainerForensic.Forensics.effect | String | Effect is the runtime audit effect | 
| PrismaCloudCompute.ContainerForensic.Forensics.listeningStartTime | Date | listeningStartTime is the port listening start time | 
| PrismaCloudCompute.ContainerForensic.Forensics.message | String | Message is the runtime audit message | 
| PrismaCloudCompute.ContainerForensic.Forensics.networkCollectionType | String | NetworkCollectionType is the type of the network collection method | 
| PrismaCloudCompute.ContainerForensic.Forensics.outbound | Boolean | Outbound indicates if the port is outbound | 
| PrismaCloudCompute.ContainerForensic.Forensics.path | String | Path is the event path | 
| PrismaCloudCompute.ContainerForensic.Forensics.pid | Number | Pid is the event process id | 
| PrismaCloudCompute.ContainerForensic.Forensics.port | Number | Port is the listening port | 
| PrismaCloudCompute.ContainerForensic.Forensics.ppid | Number | PPid is the event parent process id | 
| PrismaCloudCompute.ContainerForensic.Forensics.process | String | Process is the event process description | 
| PrismaCloudCompute.ContainerForensic.Forensics.srcIP | String | SrcIP is the source IP of the connection | 
| PrismaCloudCompute.ContainerForensic.Forensics.srcProfileID | String | SrcProfileID is the profile ID of the connection source | 
| PrismaCloudCompute.ContainerForensic.Forensics.static | Boolean | Static indicates the event was added to the profile without behavioral indication | 
| PrismaCloudCompute.ContainerForensic.Forensics.type | String | Type is the event type. | 
| PrismaCloudCompute.ContainerForensic.Forensics.timestamp | Date | Timestamp is the event timestamp | 
| PrismaCloudCompute.ContainerForensic.Forensics.user | String | User is the event user | 


#### Command Example
```!prisma-cloud-compute-profile-container-forensic-list id=container123 hostname=host123 limit=2```

#### Context Example
```json
{
    "PrismaCloudCompute": {
        "ContainerForensic": {
            "Forensics": [
                {
                    "containerId": "a6f769dd", 
                    "timestamp": "December 10, 2021 11:49:50 AM", 
                    "pid": 1341, 
                    "listeningStartTime": "January 01, 0001 00:00:00 AM", 
                    "command": "mongodump --out=/var/lib/twistlock-backup/dump", 
                    "user": "twistlock", 
                    "path": "/usr/bin/mongodump", 
                    "ppid": 15816, 
                    "type": "Process spawned"
                }, 
                {
                    "containerId": "a6f769dd", 
                    "timestamp": "December 09, 2021 11:49:22 AM", 
                    "pid": 20891, 
                    "listeningStartTime": "January 01, 0001 00:00:00 AM", 
                    "command": "mongodump --out=/var/lib/twistlock-backup/dump", 
                    "user": "twistlock", 
                    "path": "/usr/bin/mongodump", 
                    "ppid": 15816, 
                    "type": "Process spawned"
                }
            ], 
            "containerID": "container123", 
            "hostname": "host123"
        }
    }
}
```

#### Human Readable Output
### Containers forensic report
|Type|Path|User|Pid|ContainerId|Timestamp|Command|
|---|---|---|---|---|---|---|
| Process spawned | /usr/bin/mongodump | twistlock | 1341 | a6f769dd | December 10, 2021 11:49:50 AM | mongodump --out=/var/lib/twistlock-backup/dump |
| Process spawned | /usr/bin/mongodump | twistlock | 20891 | a6f769dd | December 09, 2021 11:49:22 AM | mongodump --out=/var/lib/twistlock-backup/dump |


### prisma-cloud-compute-host-forensic-list
***
Get forensics on a specific host


#### Base Command

`prisma-cloud-compute-host-forensic-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | host ID, can be retrieved from prisma-cloud-compute-profile-host-list command. | Required | 
| collections | Collections are collections scoping the query. | Optional | 
| incident_id | IncidentID is the incident ID in case the request kind is an incident. | Optional | 
| limit | maximum of forensics data records to return, must be between 1-50. Default is 20. | Optional | 
| offset | The offset number to begin listing host forensics from. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.HostForensic.Forensics.app | String | App is the application associated with the event | 
| PrismaCloudCompute.HostForensic.Forensics.attack | String | Attack is the event attack type | 
| PrismaCloudCompute.HostForensic.Forensics.category | String | Category is the incident category. | 
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
| PrismaCloudCompute.HostForensic.Forensics.type | String | Type is the event type. | 
| PrismaCloudCompute.HostForensic.Forensics.user | String | User is the event user | 
| PrismaCloudCompute.HostForensic.hostID | String | The host ID that was analyzed | 


#### Command Example
```!prisma-cloud-compute-host-forensic-list id=hostname123 limit=3 offset=5```

#### Context Example
```json
{
    "PrismaCloudCompute": {
        "HostForensic": {
            "Forensics": [
                {
                    "ppath": "/bin/bash", 
                    "timestamp": "December 10, 2021 21:36:03 PM", 
                    "app": "cron", 
                    "pid": 17478, 
                    "listeningStartTime": "January 01, 0001 00:00:00 AM", 
                    "command": "awk { printf  $3 \"|\" $2 \"|\" $1 \":\"}", 
                    "user": "cakeagent", 
                    "path": "/usr/bin/gawk", 
                    "ppid": 17475, 
                    "type": "Process spawned", 
                    "interactive": true
                }, 
                {
                    "ppath": "/bin/bash", 
                    "timestamp": "December 10, 2021 21:36:03 PM", 
                    "app": "cron", 
                    "pid": 17477, 
                    "listeningStartTime": "January 01, 0001 00:00:00 AM", 
                    "command": "grep -vE ^Filesystem|tmpfs|cdrom", 
                    "user": "cakeagent", 
                    "path": "/bin/grep", 
                    "ppid": 17475, 
                    "type": "Process spawned", 
                    "interactive": true
                }, 
                {
                    "ppath": "/bin/bash", 
                    "timestamp": "December 10, 2021 21:36:03 PM", 
                    "app": "cron", 
                    "pid": 17476, 
                    "listeningStartTime": "January 01, 0001 00:00:00 AM", 
                    "command": "df -H -P -B G", 
                    "user": "cakeagent", 
                    "path": "/bin/df", 
                    "ppid": 17475, 
                    "type": "Process spawned", 
                    "interactive": true
                }
            ], 
            "hostID": "hostname123"
        }
    }
}
```

#### Human Readable Output
### Host forensics report
|Type|Path|User|Pid|Timestamp|Command|App|
|---|---|---|---|---|---|---|
| Process spawned | /usr/bin/gawk | cakeagent | 17411 | December 10, 2021 21:34:03 PM | awk {gsub("%", "%%", $0);printf  $1 "\|" $2 "\|" $3 "\|" $4 "\|" $5 "\|" $6 "\|" $11 ":::"} | cron |
| Process spawned | /bin/ps | cakeagent | 17410 | December 10, 2021 21:34:03 PM | ps aux | cron |
| Process spawned | /bin/grep | cakeagent | 17407 | December 10, 2021 21:34:03 PM | grep -vE ^Filesystem\|tmpfs\|cdrom | cron |


### prisma-cloud-compute-console-version-info
***
Get the console version


#### Base Command

`prisma-cloud-compute-console-version-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.Console.Version | String | The console version | 


#### Command Example
```!prisma-cloud-compute-console-version-info```

#### Context Example
```json
{
    "PrismaCloudCompute": {
        "Console": {
            "Version": "21.04.439"
        }
    }
}
```

#### Human Readable Output
### Console version
|Version|
|---|
| 21.04.439 |


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
| PrismaCloudCompute.CustomFeedIP.digest | String | Digest is an internal digest of the custom ip feed | 
| PrismaCloudCompute.CustomFeedIP.feed | String | Feed is the list blacklisted custom ips | 
| PrismaCloudCompute.CustomFeedIP.modified | Date | Modified is the last time the custom feed was modified | 


#### Command Example
```!prisma-cloud-compute-custom-feeds-ip-list```

#### Context Example
```json
{
    "PrismaCloudCompute": {
        "CustomFeedIP": {
            "feed": [
                "2.2.2.2", 
                "1.1.1.1"
            ], 
            "modified": "December 10, 2021 21:12:32 PM", 
            "digest": "12345"
        }
    }
}
```

#### Human Readable Output
### IP Feeds
|Modified|Feed|
|---|---|
| December 10, 2021 21:12:32 PM | 2.2.2.2,<br>1.1.1.1 |


### prisma-cloud-compute-custom-feeds-ip-add
***
Add a list of banned IPs to be blocked by the system

### Base Command

`prisma-cloud-compute-custom-feeds-ip-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of custom ips to add to the banned IPs list that will be blocked, for example ip=1.1.1.1,2.2.2.2. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!prisma-cloud-compute-custom-feeds-ip-add IP=1.1.1.1,2.2.2.2```

#### Human Readable Output
Successfully updated the custom IP feeds


