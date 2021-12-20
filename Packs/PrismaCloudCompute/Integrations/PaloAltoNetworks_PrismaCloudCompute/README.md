Prisma™ Cloud Compute Edition delivers cloud workload protection (CWPP) for modern
enterprises, providing holistic protection across hosts, containers, and serverless deployments in any cloud, 
throughout the application lifecycle. Prisma Cloud Compute Edition is cloud native and API-enabled, 
protecting all your workloads regardless of their underlying compute technology or the cloud in which they run.

This integration lets you import **Palo Alto Networks - Prisma Cloud Compute** alerts into Cortex XSOAR.

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
   | **Prisma Cloud Compute Project Name (if applicable)** | Copy the project name from the alert profile created in Prisma Cloud Compute and paste in this field. | N/A |
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
Get information about the hosts and their profile events. This command supports asterisks which allows you to get host profiles by filtering its fields according to a specific substring.


#### Base Command

`prisma-cloud-compute-profile-host-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | A comma-separated list of profile (hostname) IDs. For example, !prisma-cloud-compute-profile-host-list hostname="*149*,*257*". | Optional | 
| limit | The maximum number of hosts and their profile events to return. Must be between 1-50. Default is 15. | Optional | 
| offset | The offset by which to begin listing hosts and their profile events. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.ProfileHost._id | String | The profile ID \(hostname\). | 
| PrismaCloudCompute.ProfileHost.accountID | String | The cloud account ID associated with the profile. | 
| PrismaCloudCompute.ProfileHost.apps.listeningPorts.command | String | The command that triggered the connection. | 
| PrismaCloudCompute.ProfileHost.apps.listeningPorts.modified | Date | The timestamp of when the event occurred. | 
| PrismaCloudCompute.ProfileHost.apps.listeningPorts.port | Number | The listening port number. | 
| PrismaCloudCompute.ProfileHost.apps.listeningPorts.processPath | String | The path to the process that uses the port. | 
| PrismaCloudCompute.ProfileHost.apps.name | String | The app name. | 
| PrismaCloudCompute.ProfileHost.apps.outgoingPorts.command | String | The command that triggered the connection. | 
| PrismaCloudCompute.ProfileHost.apps.outgoingPorts.country | String | The country ISO code for the given IP address. | 
| PrismaCloudCompute.ProfileHost.apps.outgoingPorts.ip | String | The IP address captured over this port. | 
| PrismaCloudCompute.ProfileHost.apps.outgoingPorts.modified | Date | The timestamp of when the event occurred. | 
| PrismaCloudCompute.ProfileHost.apps.outgoingPorts.port | Number | The outgoing port number. | 
| PrismaCloudCompute.ProfileHost.apps.outgoingPorts.processPath | String | The path to the process that uses the port. | 
| PrismaCloudCompute.ProfileHost.apps.processes.command | String | The executed command. | 
| PrismaCloudCompute.ProfileHost.apps.processes.md5 | String | The process binary MD5 sum. | 
| PrismaCloudCompute.ProfileHost.apps.processes.modified | Boolean | Whether the process binary was modified after the container started. | 
| PrismaCloudCompute.ProfileHost.apps.processes.path | String | The process binary path. | 
| PrismaCloudCompute.ProfileHost.apps.processes.ppath | String | The parent process path. | 
| PrismaCloudCompute.ProfileHost.apps.processes.time | Date | The time in which the process was added. If the process was modified, time is the modification time. | 
| PrismaCloudCompute.ProfileHost.apps.processes.user | String | The username of the user who started the process. | 
| PrismaCloudCompute.ProfileHost.apps.startupProcess.command | String | The executed command. | 
| PrismaCloudCompute.ProfileHost.apps.startupProcess.md5 | String | The process binary MD5 sum. | 
| PrismaCloudCompute.ProfileHost.apps.startupProcess.modified | Boolean | Whether the process binary was modified after the container started. | 
| PrismaCloudCompute.ProfileHost.apps.startupProcess.path | String | The process binary path. | 
| PrismaCloudCompute.ProfileHost.apps.startupProcess.ppath | String | The parent process path. | 
| PrismaCloudCompute.ProfileHost.apps.startupProcess.time | Date | The time in which the process was added. If the process was modified, time is the modification time. | 
| PrismaCloudCompute.ProfileHost.apps.startupProcess.user | String | The username of the user who started the process. | 
| PrismaCloudCompute.ProfileHost.collections | String | A list of collections to which this profile applies. | 
| PrismaCloudCompute.ProfileHost.created | Date | The profile creation time. | 
| PrismaCloudCompute.ProfileHost.hash | Number | The uint32 hash associated with the profile. | 
| PrismaCloudCompute.ProfileHost.labels | String | The labels associated with the profile. | 
| PrismaCloudCompute.ProfileHost.sshEvents.command | String | The executed command. | 
| PrismaCloudCompute.ProfileHost.sshEvents.country | String | The SSH client's country of origin. | 
| PrismaCloudCompute.ProfileHost.sshEvents.ip | String | The connection client IP address. | 
| PrismaCloudCompute.ProfileHost.sshEvents.loginTime | Date | The SSH login time. | 
| PrismaCloudCompute.ProfileHost.sshEvents.md5 | String | The process binary MD5 sum. | 
| PrismaCloudCompute.ProfileHost.sshEvents.modified | Boolean | Whether the process binary was modified after the container started. | 
| PrismaCloudCompute.ProfileHost.sshEvents.path | String | The process binary path. | 
| PrismaCloudCompute.ProfileHost.sshEvents.ppath | String | The parent process path. | 
| PrismaCloudCompute.ProfileHost.sshEvents.time | Date | The time in which the process was added. If the process was modified, time is the modification time. | 
| PrismaCloudCompute.ProfileHost.sshEvents.user | String | The username of the user who started the process. | 
| PrismaCloudCompute.ProfileHost.time | Date | The last time this profile was modified. | 
| PrismaCloudCompute.ProfileHost.geoip.countries.code | String | The country code of the computer that accessed the host. | 
| PrismaCloudCompute.ProfileHost.geoip.countries.ip | String | The IP address of the computer that accessed the host. | 
| PrismaCloudCompute.ProfileHost.geoip.countries.modified | Date | The last time the IP address associated with this country accessed the host console. | 
| PrismaCloudCompute.ProfileHost.geoip.modified | Date | The last time any of the country IP addresses accessed the host console. | 


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
Get information about the containers and their profile events. This command supports asterisks which allows you to get container profiles by filtering its fields according to a specific substring.


#### Base Command

`prisma-cloud-compute-profile-container-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster | A comma-separated list of runtime profile Kubernetes clusters. | Optional | 
| id | A comma-separated list of runtime profile (hostname) IDs. For example, !prisma-cloud-compute-profile-container-list id="*256*,*148*". | Optional | 
| image | A comma-separated list of runtime profile images. For example, !prisma-cloud-compute-profile-container-list image="*console*,*defender*". | Optional | 
| image_id | A comma-separated list of runtime profile image IDs. For example, !prisma-cloud-compute-profile-container-list image_id="*123*,*456*". | Optional | 
| namespace | NA comma-separated list of runtime profile Kubernetes namespaces. For example, !prisma-cloud-compute-profile-container-list namespace="*namespace1*,*namespace2*". | Optional | 
| os | A comma-separated list of service runtime profile operating systems. For example, !prisma-cloud-compute-profile-container-list os="*Red Hat*,*Windows*". | Optional | 
| state | A comma-separated list of runtime profile states. For example, !prisma-cloud-compute-profile-container-list state=*active*. | Optional | 
| limit | TThe maximum number of containers and their profile events. Must be between 1-50. Default is 15. | Optional | 
| offset | The offset by which to begin listing containers and their profile events. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.ProfileContainer._id | String | The profile ID. | 
| PrismaCloudCompute.ProfileContainer.accountsIDs | String | The cloud account IDs associated with the container runtime profile. | 
| PrismaCloudCompute.ProfileContainer.archived | Boolean | Whether this profile is archived. | 
| PrismaCloudCompute.ProfileContainer.capabilities.ci | Boolean | Whether the container is allowed to write binaries to disk and run them based on static analysis. | 
| PrismaCloudCompute.ProfileContainer.capabilities.cloudMetadata | Boolean | Whether the given container can query cloud metadata API based on static analysis. | 
| PrismaCloudCompute.ProfileContainer.capabilities.dnsCache | Boolean | Whether the DNS services used by all the pods in the cluster were added to the profile based on static analysis. | 
| PrismaCloudCompute.ProfileContainer.capabilities.dynamicDNSQuery | Boolean | Whether capped behavioral DNS queries were added to the profile based on static analysis. | 
| PrismaCloudCompute.ProfileContainer.capabilities.dynamicFileCreation | Boolean | Whether capped behavioral file system paths were added to the profile based on static analysis. | 
| PrismaCloudCompute.ProfileContainer.capabilities.dynamicProcessCreation | Boolean | Whether capped behavioral processes were added to the profile based on static analysis. | 
| PrismaCloudCompute.ProfileContainer.capabilities.k8s | Boolean | Whether the given container can perform Kubernetes networking tasks (e.g., contact to API server). | 
| PrismaCloudCompute.ProfileContainer.capabilities.proxy | Boolean | Whether the container can listen on any port and perform multiple outbound connections. | 
| PrismaCloudCompute.ProfileContainer.capabilities.sshd | Boolean | Whether the container can run sshd processes. | 
| PrismaCloudCompute.ProfileContainer.capabilities.unpacker | Boolean | Whether the container is allowed to write shared libraries to disk. | 
| PrismaCloudCompute.ProfileContainer.cluster | String | The provided cluster name. | 
| PrismaCloudCompute.ProfileContainer.collections | String | Collections to which this profile applies. | 
| PrismaCloudCompute.ProfileContainer.created | Date | The profile creation time. | 
| PrismaCloudCompute.ProfileContainer.entrypoint | String | The image entrypoint. | 
| PrismaCloudCompute.ProfileContainer.events._id | String | The history event entity. | 
| PrismaCloudCompute.ProfileContainer.events.command | String | The process that was executed. | 
| PrismaCloudCompute.ProfileContainer.events.hostname | String | The hostname on which the command was invoked. | 
| PrismaCloudCompute.ProfileContainer.events.time | Date | The time of the event. | 
| PrismaCloudCompute.ProfileContainer.filesystem.behavioral.mount | Boolean | Whether the given folder is mounted. | 
| PrismaCloudCompute.ProfileContainer.filesystem.behavioral.path | String | The file path. | 
| PrismaCloudCompute.ProfileContainer.filesystem.behavioral.process | String | The process that accessed the file. | 
| PrismaCloudCompute.ProfileContainer.filesystem.behavioral.time | Date | The time in which the file was added. | 
| PrismaCloudCompute.ProfileContainer.filesystem.static.mount | Boolean | Whether the given folder is a mounted. | 
| PrismaCloudCompute.ProfileContainer.filesystem.static.path | String | The file path. | 
| PrismaCloudCompute.ProfileContainer.filesystem.static.process | String | The process that accessed the file. | 
| PrismaCloudCompute.ProfileContainer.filesystem.static.time | Date | The time in which the file was added. | 
| PrismaCloudCompute.ProfileContainer.hash | Number | The uint32 hash associated with the profile. | 
| PrismaCloudCompute.ProfileContainer.hostNetwork | Boolean | Whether the instance shares the network namespace with the host. | 
| PrismaCloudCompute.ProfileContainer.hostPid | Boolean | Whether the instance shares the PID namespace with the host. | 
| PrismaCloudCompute.ProfileContainer.image | String | The image the container runs with. | 
| PrismaCloudCompute.ProfileContainer.imageID | String | The profile's image ID. | 
| PrismaCloudCompute.ProfileContainer.infra | Boolean | Whether this is an infrastructure container. | 
| PrismaCloudCompute.ProfileContainer.istio | Boolean | Whether it is an Istio-monitored profile. | 
| PrismaCloudCompute.ProfileContainer.k8s.clusterRoles.labels.key | String | The key of the label. | 
| PrismaCloudCompute.ProfileContainer.k8s.clusterRoles.labels.value | String | The value of the label. | 
| PrismaCloudCompute.ProfileContainer.k8s.clusterRoles.name | String | The role name. | 
| PrismaCloudCompute.ProfileContainer.k8s.clusterRoles.roleBinding | String | The name of the role binding used for display. | 
| PrismaCloudCompute.ProfileContainer.k8s.clusterRoles.rules | String | The list of rules associated with the cluster role. | 
| PrismaCloudCompute.ProfileContainer.k8s.roles.labels.key | String | The key of the label. | 
| PrismaCloudCompute.ProfileContainer.k8s.roles.labels.value | String | The value of the label. | 
| PrismaCloudCompute.ProfileContainer.k8s.roles.name | String | The kubernetes role name. | 
| PrismaCloudCompute.ProfileContainer.k8s.roles.namespace | String | The namespace associated with the role. | 
| PrismaCloudCompute.ProfileContainer.k8s.roles.roleBinding | String | The name of the role binding used for display. | 
| PrismaCloudCompute.ProfileContainer.k8s.roles.rules | String | The policy rules associated with the role. | 
| PrismaCloudCompute.ProfileContainer.k8s.serviceAccount | String | The service account used to access Kubernetes API server. This field will be empty if the container is not running inside of a pod. | 
| PrismaCloudCompute.ProfileContainer.label | String | The profile's label. | 
| PrismaCloudCompute.ProfileContainer.lastUpdate | Date | The last time this profile was modified. | 
| PrismaCloudCompute.ProfileContainer.learnedStartup | Boolean | Whether the startup events were learned. | 
| PrismaCloudCompute.ProfileContainer.namespace | String | The Kubernetes deployment namespace. | 
| PrismaCloudCompute.ProfileContainer.network.behavioral.dnsQueries.domainName | String | The queried domain name. | 
| PrismaCloudCompute.ProfileContainer.network.behavioral.dnsQueries.domainType | String | The queried domain type. | 
| PrismaCloudCompute.ProfileContainer.network.listeningPorts.app | String | The name of the app. | 
| PrismaCloudCompute.ProfileContainer.network.listeningPorts.portsData.all | Boolean | Whether this port data represents any arbitrary ports. | 
| PrismaCloudCompute.ProfileContainer.network.listeningPorts.portsData.ports.port | Number | The port number. | 
| PrismaCloudCompute.ProfileContainer.network.listeningPorts.portsData.ports.time | Date | The learning timestamp of this port. | 
| PrismaCloudCompute.ProfileContainer.network.outboundPorts.portsData.all | Boolean | Whether this port data represents any arbitrary ports. | 
| PrismaCloudCompute.ProfileContainer.network.outboundPorts.portsData.ports.port | Number | The port number. | 
| PrismaCloudCompute.ProfileContainer.network.static.listeningPorts.ports.time | Date | The learning timestamp of this port. | 
| PrismaCloudCompute.ProfileContainer.network.static.listeningPorts.app | String | The name of the app. | 
| PrismaCloudCompute.ProfileContainer.network.static.listeningPorts.portsData.all | Boolean | Whether this port data represents any arbitrary ports. | 
| PrismaCloudCompute.ProfileContainer.network.static.listeningPorts.portsData.ports.port | Number | The port number. | 
| PrismaCloudCompute.ProfileContainer.network.static.listeningPorts.portsData.ports.time | Date | The learning timestamp of this port. | 
| PrismaCloudCompute.ProfileContainer.os | String | The profile image operating system. | 
| PrismaCloudCompute.ProfileContainer.processes.behavioral.command | String | The executed command. | 
| PrismaCloudCompute.ProfileContainer.processes.behavioral.md5 | String | The process binary MD5 sum. | 
| PrismaCloudCompute.ProfileContainer.processes.behavioral.modified | Boolean | Whether the process binary was modified after the container started. | 
| PrismaCloudCompute.ProfileContainer.processes.behavioral.path | String | The process binary path. | 
| PrismaCloudCompute.ProfileContainer.processes.behavioral.ppath | String | The parent process path. | 
| PrismaCloudCompute.ProfileContainer.processes.behavioral.time | Date | The time in which the process was added. If the process was modified, time is the modification time. | 
| PrismaCloudCompute.ProfileContainer.processes.behavioral.user | String | The username of the user who started the process. | 
| PrismaCloudCompute.ProfileContainer.processes.static.command | String | The executed command. | 
| PrismaCloudCompute.ProfileContainer.processes.static.md5 | String | The process binary MD5 sum. | 
| PrismaCloudCompute.ProfileContainer.processes.static.modified | Boolean | Whether the process binary was modified after the container started. | 
| PrismaCloudCompute.ProfileContainer.processes.static.path | String | The process binary path. | 
| PrismaCloudCompute.ProfileContainer.processes.static.ppath | String | The parent process path. | 
| PrismaCloudCompute.ProfileContainer.processes.static.time | Date | The time in which the process was added. If the process was modified, time is the modification time. | 
| PrismaCloudCompute.ProfileContainer.processes.static.user | String | The username of the user who started the process. | 
| PrismaCloudCompute.ProfileContainer.relearningCause | String | The reason a profile entered the learning mode after being activated. | 
| PrismaCloudCompute.ProfileContainer.remainingLearningDurationSec | Number | The total time left that the system needs to finish learning this image. | 
| PrismaCloudCompute.ProfileContainer.state | String | The current state of the profile. | 


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
|Type|Path|DetectionTime|
|---|---|---|
| static | /usr/bin/mongodump | January 01, 2021 00:00:00 AM |
| static | /usr/bin/mongorestore | January 01, 2021 00:00:00 AM |
| behavioral | /usr/local/bin/fsmon | September 02, 2021 11:05:08 AM |
| behavioral | /usr/lib/apt/methods/gpgv | November 24, 2021 15:12:28 PM |

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
| id | Container profile ID. Can be retrieved from the prisma-cloud-compute-profile-container-list command. | Required | 
| limit | The maximum number of hosts to return. Must be between 1-50. Default is 50. | Optional | 
| offset | The offset by which to begin listing hosts of the container. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.ProfileContainerHost.containerID | String | The container ID. | 
| PrismaCloudCompute.ProfileContainerHost.hostsIDs | String | The list of hosts where this container is running. | 


#### Command Example
```!prisma-cloud-compute-profile-container-hosts-list id=container123```

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
| host1,<br>host2 |

### prisma-cloud-compute-profile-container-forensic-list
***
Get runtime forensics data for a specific container on a specific host.


#### Base Command

`prisma-cloud-compute-profile-container-forensic-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The container ID. Can be retrieved from the prisma-cloud-compute-profile-container-list command. | Required | 
| collections | The collections scoping the query. | Optional | 
| hostname | The hostname for which data should be fetched. | Required | 
| incident_id | The incident ID in case the request type is an incident. | Optional | 
| limit | The maximum number of forensics data records to return. Must be between 1-50. Default is 20. | Optional | 
| offset | The offset by which to begin listing records from. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.ContainerForensic.containerID | String | The container ID. | 
| PrismaCloudCompute.ContainerForensic.hostname | String | The hostname. | 
| PrismaCloudCompute.ContainerForensic.Forensics.allPorts | Boolean | Whether all listening ports are allowed. | 
| PrismaCloudCompute.ContainerForensic.Forensics.attack | String | The event attack type. | 
| PrismaCloudCompute.ContainerForensic.Forensics.category | String | The incident category. | 
| PrismaCloudCompute.ContainerForensic.Forensics.command | String | The event command. | 
| PrismaCloudCompute.ContainerForensic.Forensics.containerId | String | The event container ID. | 
| PrismaCloudCompute.ContainerForensic.Forensics.dstIP | String | The destination IP address of the connection | 
| PrismaCloudCompute.ContainerForensic.Forensics.dstPort | String | The destination port. | 
| PrismaCloudCompute.ContainerForensic.Forensics.dstProfileID | String | The profile ID of the connection destination. | 
| PrismaCloudCompute.ContainerForensic.Forensics.effect | String | The runtime audit effect. | 
| PrismaCloudCompute.ContainerForensic.Forensics.listeningStartTime | Date | The port listening start time. | 
| PrismaCloudCompute.ContainerForensic.Forensics.message | String | The runtime audit message. | 
| PrismaCloudCompute.ContainerForensic.Forensics.networkCollectionType | String | The type of the network collection method. | 
| PrismaCloudCompute.ContainerForensic.Forensics.outbound | Boolean | Whether the port is outbound. | 
| PrismaCloudCompute.ContainerForensic.Forensics.path | String | The event path. | 
| PrismaCloudCompute.ContainerForensic.Forensics.pid | Number | The event process ID. | 
| PrismaCloudCompute.ContainerForensic.Forensics.port | Number | The listening port. | 
| PrismaCloudCompute.ContainerForensic.Forensics.ppid | Number | The event parent process ID. | 
| PrismaCloudCompute.ContainerForensic.Forensics.process | String | The event process description. | 
| PrismaCloudCompute.ContainerForensic.Forensics.srcIP | String | The source IP of the connection | 
| PrismaCloudCompute.ContainerForensic.Forensics.srcProfileID | String | The profile ID of the connection source. | 
| PrismaCloudCompute.ContainerForensic.Forensics.static | Boolean | Whether the event was added to the profile without behavioral indications. | 
| PrismaCloudCompute.ContainerForensic.Forensics.type | String | The event type. | 
| PrismaCloudCompute.ContainerForensic.Forensics.timestamp | Date | The event timestamp. | 
| PrismaCloudCompute.ContainerForensic.Forensics.user | String | The event user. | 


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
Get forensics on a specific host.


#### Base Command

`prisma-cloud-compute-host-forensic-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The host ID. Can be retrieved from the prisma-cloud-compute-profile-host-list command. | Required | 
| collections | The collections scoping the query. | Optional | 
| incident_id | The incident ID in case the request type is an incident. | Optional | 
| limit | The maximum number of forensics data records to return. Must be between 1-50. Default is 20. | Optional | 
| offset | The offset by which to begin listing host forensics from. Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.HostForensic.Forensics.app | String | The application associated with the event. | 
| PrismaCloudCompute.HostForensic.Forensics.attack | String | The event attack type. | 
| PrismaCloudCompute.HostForensic.Forensics.category | String | The incident category. | 
| PrismaCloudCompute.HostForensic.Forensics.command | String | The event command. | 
| PrismaCloudCompute.HostForensic.Forensics.country | String | The country associated with the event. | 
| PrismaCloudCompute.HostForensic.Forensics.effect | String | The runtime audit effect. | 
| PrismaCloudCompute.HostForensic.Forensics.interactive | Boolean | Whether the event is interactive. | 
| PrismaCloudCompute.HostForensic.Forensics.ip | String | The IP address associated with the event. | 
| PrismaCloudCompute.HostForensic.Forensics.listeningStartTime | Date | The listening port start time. | 
| PrismaCloudCompute.HostForensic.Forensics.message | String | The runtime audit message. | 
| PrismaCloudCompute.HostForensic.Forensics.path | String | The event path. | 
| PrismaCloudCompute.HostForensic.Forensics.pid | Number | The event process ID. | 
| PrismaCloudCompute.HostForensic.Forensics.port | Number | The listening port. | 
| PrismaCloudCompute.HostForensic.Forensics.ppath | String | The event parent path. | 
| PrismaCloudCompute.HostForensic.Forensics.ppid | Number | The event parent process ID. | 
| PrismaCloudCompute.HostForensic.Forensics.process | String | The event process. | 
| PrismaCloudCompute.HostForensic.Forensics.timestamp | Date | The event timestamp. | 
| PrismaCloudCompute.HostForensic.Forensics.type | String | The event type. | 
| PrismaCloudCompute.HostForensic.Forensics.user | String | The event user. | 
| PrismaCloudCompute.HostForensic.hostID | String | The host ID that was analyzed. | 


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
Get the console version.


#### Base Command

`prisma-cloud-compute-console-version-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.Console.Version | String | The console version. | 


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
Get all the blacklisted IP addresses in the system.


#### Base Command

`prisma-cloud-compute-custom-feeds-ip-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.CustomFeedIP.digest | String | An internal digest of the custom IP feed. | 
| PrismaCloudCompute.CustomFeedIP.feed | String | The list of blacklisted custom IP addresses. | 
| PrismaCloudCompute.CustomFeedIP.modified | Date | The last time the custom feed was modified. | 


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
Add a list of banned IP addresses to be blocked by the system.

### Base Command

`prisma-cloud-compute-custom-feeds-ip-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of custom IP addresses to add to the banned IPs list that will be blocked. For example ip=1.1.1.1,2.2.2.2. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!prisma-cloud-compute-custom-feeds-ip-add IP=1.1.1.1,2.2.2.2```

#### Human Readable Output
Successfully updated the custom IP feeds


