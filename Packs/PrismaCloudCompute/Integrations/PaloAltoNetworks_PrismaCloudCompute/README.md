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
| prismaCloudCompute.containerForensic.ContainerID | String | Container ID of the forensic | 
| prismaCloudCompute.containerForensic.Hostname | String | The Hostname | 


#### Command Example
```!prisma-cloud-compute-profile-container-forensic-list id=123 hostname=hostname1```

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
### prisma-cloud-compute-host-forensic-list
***
Get forensics on a specific host


#### Base Command

`prisma-cloud-compute-host-forensic-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | host ID. | Required | 
| collections | Collections are collections scoping the query. | Optional | 
| hostname | Hostname is the hostname for which data should be fetched. | Optional | 
| incidentID | IncidentID is the incident ID in case the request kind is an incident. | Optional | 
| eventTime | EventTime is the forensic event pivot time in milliseconds (used to fetch events). | Optional | 
| format | Format is the forensic data format. | Optional | 
| limit | maximum of forensics data records to return. Default is 20. | Optional | 
| offset | The offset number to begin listing host forensics from . Default is 0. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| prismaCloudCompute.hostForensic.app | String | App is the application associated with the event | 
| prismaCloudCompute.hostForensic.attack | Unknown | Attack is the event attack type | 
| prismaCloudCompute.hostForensic.category | Unknown | Category is the incident category. | 
| prismaCloudCompute.hostForensic command | String | Command is the event command | 
| prismaCloudCompute.hostForensic.country | String | Country is the country associated with the event | 
| prismaCloudCompute.hostForensic.effect | String | Effect is the runtime audit effect | 
| prismaCloudCompute.hostForensic.interactive | Boolean | Interactive indicates if the event is interactive | 
| prismaCloudCompute.hostForensic.ip | String | IP is the IP address associated with the event | 
| prismaCloudCompute.hostForensic.listeningStartTime | Date | ListeningStartTime is the listening port start time | 
| prismaCloudCompute.hostForensic.message | String | Message is the runtime audit message | 
| prismaCloudCompute.hostForensic.path | String | Path is the event path | 
| prismaCloudCompute.hostForensic.pid | Number | Pid is the event process id | 
| prismaCloudCompute.hostForensic.port | Number | Port is the listening port | 
| prismaCloudCompute.hostForensic.ppath | String | P-path is the event parent path | 
| prismaCloudCompute.hostForensic.ppid | Number | PPid is the event parent process id | 
| prismaCloudCompute.hostForensic.process | String | Process is the event process | 
| prismaCloudCompute.hostForensic.timestamp | Date | Timestamp is the event timestamp | 
| prismaCloudCompute.hostForensic.type | Unknown | Type is the event type. | 
| prismaCloudCompute.hostForensic.user | Unknown | User is the event user | 


#### Command Example
```!prisma-cloud-compute-host-forensic-list id=hostID limit=5```

#### Human Readable Output
### Host forensics report
|type|app|path|command|
|---|---|---|---|
| Process spawned | demisto | /usr/bin/docker | docker ps -a |
| Process spawned | demisto | /usr/bin/docker | docker ps -a |
| Process spawned | cron | /usr/bin/wget | wget -q -o /dev/null -O /etc/cakeagent/cakelog.log -T 30 --post-data user=devopsdemistocom&secret=dT |
| Process spawned | cron | /usr/bin/gawk | awk {gsub("%", "%%", $0);printf  $1 "\|" $2 "\|" $3 "\|" $4 "\|" $5 "\|" $6 "\|" $11 ":::"} |
| Process spawned | cron | /bin/ps | ps aux |

### prisma-cloud-compute-console-version-info
***
Get the console version. 


#### Base Command

`prisma-cloud-compute-console-version-info`

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| prismaCloudCompute.console.version | String | The console version | 


#### Command Example
```!prisma-cloud-compute-console-version-info```

#### Human Readable Output
### Console version
|version|
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
| prismaCloudCompute.customFeedIP._id | String | ID is the custom feed id | 
| prismaCloudCompute.customFeedIP.digest | String | Digest is an internal digest of the custom ip feed | 
| prismaCloudCompute.customFeedIP.feed  | Unknown | Feed is the list of custom ips | 
| prismaCloudCompute.customFeedIP.modified | Date | Modified is the last time the custom feed was modified | 


#### Command Example
```!prisma-cloud-compute-custom-feeds-ip-list```

#### Human Readable Output
### IP Feeds
|modified|feed|
|---|---|
| November 30, 2021 20:47:06 PM | 4.4.4.4,<br>1.1.1.1,<br>2.2.2.2,<br>3.3.3.3 |


### prisma-cloud-compute-custom-feeds-ip-add
***
Add a list of banned IPs to be blocked by the system


#### Base Command

`prisma-cloud-compute-custom-feeds-ip-add`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| IP | List of custom ips to add to the banned IPs list that will be blocked. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!prisma-cloud-compute-custom-feeds-ip-add IP=1.1.1.1,2.2.2.2```

#### Human Readable Output
### IP Feeds
|Feeds|
|---|
| 2.2.2.2,<br>1.1.1.1 |

