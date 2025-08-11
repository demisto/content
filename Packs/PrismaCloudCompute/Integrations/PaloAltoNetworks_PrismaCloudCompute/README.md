Prisma™ Cloud Compute Edition delivers cloud workload protection (CWPP) for modern
enterprises, providing holistic protection across hosts, containers, and serverless deployments in any cloud,
throughout the application lifecycle. Prisma Cloud Compute Edition is cloud native and API-enabled,
protecting all your workloads regardless of their underlying compute technology or the cloud in which they run.

This integration lets you import *Palo Alto Networks - Prisma Cloud Compute* alerts into Cortex XSOAR.

## Configure Prisma Cloud Compute to Send Alerts to Cortex XSOAR

To send alerts from Prisma Cloud Compute to Cortex XSOAR, you need to create an alert profile.

1. Log in to your Prisma Cloud Compute console.
2. Navigate to **Manage > Alerts**.
3. Click **Add Profile** to create a new alert profile.
4. On the left, select **Demisto** from the provider list.
5. On the right, select the alert triggers. Alert triggers specify which alerts are sent to Cortex XSOAR.
6. Click **Save** to save the alert profile.
7. Make sure you configure the user role to be at least `auditor`, otherwise you will not be able to fetch the alerts.

## Configure Prisma Cloud Compute in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Fetch incidents |  | False |
| Prisma Cloud Compute Console URL and Port | URL address and port of your Prisma Cloud Compute console. Copy the address from the alert profile created in Prisma Cloud Compute, for example https://example.net:1234 | True |
| Prisma Cloud Compute Project Name (if applicable) | Copy the project name from the alert profile created in Prisma Cloud Compute and paste in this field. | False |
| Trust any certificate (not secure) | Skips verification of the CA certificate \(not recommended\). | False |
| Use system proxy settings | Runs the integration instance using the proxy server \(HTTP or HTTPS\) that you defined in the server configuration. | False |
| Username | Prisma Cloud Compute login credentials. | True |
| Password |  | True |
| Prisma Cloud Compute CA Certificate | CA Certificate used by Prisma Cloud Compute. Copy the certificate from the alert profile created in Prisma Cloud Compute. | False |
| Incident type |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
| Incidents Fetch Interval |  | False |


## Configure Prisma Cloud Compute User Roles

* In order to access Prisma Cloud Compute resources, a user must be assigned with a role.
* Without sufficient user roles, commands/fetching incidents might not work.
* See below the user roles and their descriptions.
* See 'Requires Role' section (each command requires a different type of role).

1) Go to `Manage` -> `Authentication`.

2) Choose the user that you want to edit roles -> `Actions` -> Press `...`.

3) Press on `Edit` -> Choose a Role in the `Role` section.

![User Roles Configuration](../../doc_files/user-roles-configuration.png)

## Required User Roles

In order to use the entire integration commands a user must have the permissions of the following user roles:

* devSecOps
* ci
* auditor
* operator
* devOps
* vulnerabilityManager

The administrator user role can use the entire integration commands.

See user roles descriptions in Prisma Cloud Compute:
![Available User Roles](../../doc_files/available-user-roles.png)

Commands
--------

You can execute these commands from the CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

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

### prisma-cloud-compute-profile-container-list

***
Get information about the containers and their profile events. This command supports asterisks which allows you to get container profiles by filtering its fields according to a specific substring.

#### Base Command

`prisma-cloud-compute-profile-container-list`

#### Requires Role

devSecOps

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster | A comma-separated list of runtime profile Kubernetes clusters. | Optional |
| id | A comma-separated list of runtime profile (hostname) IDs. For example, !prisma-cloud-compute-profile-container-list id="*256*,*148*". | Optional |
| image | A comma-separated list of runtime profile images. For example, !prisma-cloud-compute-profile-container-list image="*console*,*defender*". | Optional |
| image_id | A comma-separated list of runtime profile image IDs. For example, !prisma-cloud-compute-profile-container-list image_id="*123*,*456*". | Optional |
| namespace | A comma-separated list of runtime profile Kubernetes namespaces. For example, !prisma-cloud-compute-profile-container-list namespace="*namespace1*,*namespace2*". | Optional |
| os | A comma-separated list of service runtime profile operating systems. For example, !prisma-cloud-compute-profile-container-list os="*Red Hat*,*Windows*". | Optional |
| state | A comma-separated list of runtime profile states. For example, !prisma-cloud-compute-profile-container-list state=*active*. | Optional |
| limit | The maximum number of containers and their profile events. Must be between 1-50. Default is 15. | Optional |
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
| PrismaCloudCompute.ProfileContainer.k8s.roles.name | String | The Kubernetes role name. |
| PrismaCloudCompute.ProfileContainer.k8s.roles.namespace | String | The namespace associated with the role. |
| PrismaCloudCompute.ProfileContainer.k8s.roles.roleBinding | String | The name of the role binding used for display. |
| PrismaCloudCompute.ProfileContainer.k8s.roles.rules | String | The policy rules associated with the role. |
| PrismaCloudCompute.ProfileContainer.k8s.serviceAccount | String | The service account used to access the Kubernetes API server. This field will be empty if the container is not running inside of a pod. |
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
| namespace | A comma-separated list of runtime profile Kubernetes namespaces. For example, !prisma-cloud-compute-profile-container-list namespace="*namespace1*,*namespace2*". | Optional | 
| os | A comma-separated list of service runtime profile operating systems. For example, !prisma-cloud-compute-profile-container-list os="*Red Hat*,*Windows*". | Optional | 
| state | A comma-separated list of runtime profile states. For example, !prisma-cloud-compute-profile-container-list state=*active*. | Optional | 
| limit | The maximum number of containers and their profile events. Must be between 1-50. Default is 15. | Optional | 
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
| PrismaCloudCompute.ProfileContainer.capabilities.k8s | Boolean | Whether the given container can perform Kubernetes networking tasks \(e.g., contact to API server\). | 
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
| PrismaCloudCompute.ProfileContainer.filesystem.static.mount | Boolean | Whether the given folder is mounted. | 
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
| PrismaCloudCompute.ProfileContainer.k8s.roles.name | String | The Kubernetes role name. | 
| PrismaCloudCompute.ProfileContainer.k8s.roles.namespace | String | The namespace associated with the role. | 
| PrismaCloudCompute.ProfileContainer.k8s.roles.roleBinding | String | The name of the role binding used for display. | 
| PrismaCloudCompute.ProfileContainer.k8s.roles.rules | String | The policy rules associated with the role. | 
| PrismaCloudCompute.ProfileContainer.k8s.serviceAccount | String | The service account used to access the Kubernetes API server. This field will be empty if the container is not running inside of a pod. | 
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

```

#### Human Readable Output
>
>### Containers forensic report
>
>|Type|Path|User|Pid|ContainerId|Timestamp|Command|
>|---|---|---|---|---|---|---|
>| Process spawned | /usr/bin/mongodump | twistlock | 1341 | a6f769dd | December 10, 2021 11:49:50 AM | mongodump --out=/var/lib/twistlock-backup/dump |
>| Process spawned | /usr/bin/mongodump | twistlock | 20891 | a6f769dd | December 09, 2021 11:49:22 AM | mongodump --out=/var/lib/twistlock-backup/dump |

### prisma-cloud-compute-host-forensic-list

***
Get forensics on a specific host.

#### Base Command

`prisma-cloud-compute-host-forensic-list`

#### Requires Role

devSecOps

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
>
>### Host forensics report
>
>|Type|Path|User|Pid|Timestamp|Command|App|
>|---|---|---|---|---|---|---|
>| Process spawned | /usr/bin/gawk | cakeagent | 17411 | December 10, 2021 21:34:03 PM | awk {gsub("%", "%%", $0);printf  $1 "\|" $2 "\|" $3 "\|" $4 "\|" $5 "\|" $6 "\|" $11 ":::"} | cron |
>| Process spawned | /bin/ps | cakeagent | 17410 | December 10, 2021 21:34:03 PM | ps aux | cron |
>| Process spawned | /bin/grep | cakeagent | 17407 | December 10, 2021 21:34:03 PM | grep -vE ^Filesystem\|tmpfs\|cdrom | cron |

### prisma-cloud-compute-console-version-info

***
Get the console version.

#### Base Command

`prisma-cloud-compute-console-version-info`

#### Requires Role

ci

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
### prisma-cloud-compute-profile-container-hosts-list

***
Get the hosts where a specific container is running.

#### Base Command

`prisma-cloud-compute-profile-container-hosts-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Container profile ID. Can be retrieved from the "prisma-cloud-compute-profile-container-list" command. | Required | 
| limit | The maximum number of hosts to return. Must be between 1-50. Default is 50. | Optional | 
| offset | The offset by which to begin listing hosts of the container. Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.ProfileContainerHost.containerID | String | The container ID. | 
| PrismaCloudCompute.ProfileContainerHost.hostsIDs | String | The list of hosts where this container is running. | 

#### Human Readable Output
>
>### IP Feeds
>
>|Modified|Feed|
>|---|---|
>| December 10, 2021 21:12:32 PM | 2.2.2.2,<br>1.1.1.1 |

### prisma-cloud-compute-custom-feeds-ip-add

***
Add a list of banned IP addresses to be blocked by the system.

#### Base Command

`prisma-cloud-compute-custom-feeds-ip-add`

#### Requires Role

operator

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of custom IP addresses to add to the banned IPs list that will be blocked. For example ip=1.1.1.1,2.2.2.2. | Required |

#### Context Output

There is no context output for this command.

#### Command Example
### prisma-cloud-compute-profile-container-forensic-list

***
Get runtime forensics data for a specific container on a specific. host.

#### Base Command

`prisma-cloud-compute-profile-container-forensic-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The container ID. Can be retrieved from the "prisma-cloud-compute-profile-container-list" command. | Required | 
| collections | The collections scoping the query. | Optional | 
| hostname | The hostname for which data should be fetched. Can be retrieved from the "prisma-cloud-compute-hosts-list" command. | Required | 
| incident_id | A comma-separated list of incident IDs if the request type is an incident. | Optional | 
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
| PrismaCloudCompute.ContainerForensic.Forensics.dstIP | String | The destination IP address of the connection. | 
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
| PrismaCloudCompute.ContainerForensic.Forensics.srcIP | String | The source IP address of the connection. | 
| PrismaCloudCompute.ContainerForensic.Forensics.srcProfileID | String | The profile ID of the connection source. | 
| PrismaCloudCompute.ContainerForensic.Forensics.static | Boolean | Whether the event was added to the profile without behavioral indications. | 
| PrismaCloudCompute.ContainerForensic.Forensics.type | String | The event type. | 
| PrismaCloudCompute.ContainerForensic.Forensics.timestamp | Date | The event timestamp. | 
| PrismaCloudCompute.ContainerForensic.Forensics.user | String | The event user. | 


### prisma-cloud-compute-custom-feeds-malware-add

***
Add custom md5 malware hashes.

#### Base Command

`prisma-cloud-compute-custom-feeds-malware-add`

#### Requires Role

operator

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name that will be attached to the md5 records. | Required |
| md5 | Comma-separated list of md5 hashes to be added. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!prisma-cloud-compute-custom-feeds-malware-add name=test md5=md5_hash1,md5_hash2,md5_hash3```

#### Human Readable Output
>
>Successfully updated the custom md5 malware feeds

### cve

***
Get information about the CVEs in the system. Will return a maximum of 50 records. It is possible to query for a partial CVE description such as cve-2020 or cve-2014 or by severity/distro/package.

#### Base Command

`cve`

#### Requires Role

devOps

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
### prisma-cloud-compute-host-forensic-list

***
Get forensics on a specific host.

#### Base Command

`prisma-cloud-compute-host-forensic-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The host ID. Can be retrieved from the "prisma-cloud-compute-hosts-list" command. | Required | 
| collections | A comma-separated list of collections. | Optional | 
| incident_id | A comma-separated list of incident IDs in case the request type is an incident. | Optional | 
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

| PrismaCloudCompute.DefenderDetails.tasClusterID | String | The ID used to identify the TAS cluster of the defender. Typically will be the cloud controller API address |
| PrismaCloudCompute.DefenderDetails.type | String | The type of the defender \(registry scanner/kubernetes node/etc...\). |
| PrismaCloudCompute.DefenderDetails.version | String | The agent version. |

#### Command Example

```!prisma-cloud-compute-defenders-list connected=true limit=1```

#### Context Example

```json
{
    "PrismaCloudCompute": {
        "DefenderDetails": {
            "category": "container", 
            "cloudMetadata": {
                "resourceID": "123", 
                "image": "image name", 
                "provider": "aws", 
                "type": "c5.xlarge", 
                "region": "aws region", 
                "accountID": "1234"
            }, 
            "hostname": "host1", 
            "features": {
                "proxyListenerType": "none"
            }, 
            "compatibleVersion": true, 
            "lastModified": "September 02, 2021 11:05:08 AM", 
            "firewallProtection": {
                "supported": false, 
                "enabled": false
            }, 
            "fqdn": "host1.lab.com", 
            "remoteMgmtSupported": true, 
            "status": {
                "container": {
                    "scanTime": "2021-12-13T11:05:14.178Z", 
                    "completed": true
                }, 
                "features": {
                    "err": ""
                }, 
                "process": {
                    "enabled": true, 
                    "err": ""
                }, 
                "lastModified": "0001-01-01T00:00:00Z", 
                "appFirewall": {
                    "enabled": true, 
                    "err": ""
                }, 
                "hostNetworkFirewall": {
                    "enabled": true, 
                    "err": ""
                }, 
                "hostCustomCompliance": {
                    "err": ""
                }, 
                "filesystem": {
                    "enabled": true, 
                    "err": ""
                }, 
                "runtime": {
                    "enabled": true, 
                    "err": ""
                }, 
                "image": {
                    "scanTime": "2021-12-13T14:19:36.09Z", 
                    "completed": true
                }, 
                "containerNetworkFirewall": {
                    "enabled": true, 
                    "err": ""
                }, 
                "network": {
                    "enabled": true, 
                    "err": ""
                }
            }, 
            "version": "21.04.439", 
            "collections": [
                "All", 
                "123"
            ], 
            "proxy": {
                "httpProxy": "", 
                "ca": "", 
                "password": {
                    "encrypted": ""
                }, 
                "noProxy": "", 
                "user": ""
            }, 
            "systemInfo": {
                "kernelVersion": "4.14.123-111.109.amzn2.x86_64", 
                "totalDiskSpaceGB": 199, 
                "cpuCount": 4, 
                "freeDiskSpaceGB": 180, 
                "memoryGB": 7.446006774902344
            }, 
            "connected": true, 
            "remoteLoggingSupported": true, 
            "type": "docker", 
            "port": 8084, 
            "certificateExpiration": "2024-09-01T11:00:00Z"
        }
    }
}
```

#### Human Readable Output
>
>### Defenders Information
>
>|Hostname|Version|Status|Listener|
>|---|---|---|---|
>| host1 | 21.04.439 | Connected since September 02, 2021 11:05:08 AM | none

### prisma-cloud-compute-collections-list

***
Retrieves a list of all collections.

#### Base Command

`prisma-cloud-compute-collections-list`

#### Requires Role

auditor

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | The maximum number of records of collections to return. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.Collection.accountIDs | String | A list of the cloud account IDs |
| PrismaCloudCompute.Collection.appIDs | String | A list of application IDs. |
| PrismaCloudCompute.Collection.clusters | String | A list of Kubernetes cluster names. |
| PrismaCloudCompute.Collection.codeRepos | String | A list of remote code repositories. |
| PrismaCloudCompute.Collection.color | String | A color code associated with the collection. |
| PrismaCloudCompute.Collection.containers | String | A list of containers that are associated with this collection. |
| PrismaCloudCompute.Collection.description | String | A free-text description of the collection. |
| PrismaCloudCompute.Collection.functions | String | A list of functions that are associated with this collection |
| PrismaCloudCompute.Collection.hosts | String | A list of hosts that are associated with this collection |
| PrismaCloudCompute.Collection.images | String | A list of images that are associated with this collection |
| PrismaCloudCompute.Collection.labels | String | A list of labels that are associated with this collection. |
| PrismaCloudCompute.Collection.modified | Date | The timestamp if when the collection was last modified. |
| PrismaCloudCompute.Collection.name | String | A unique name associated with the collection. |
| PrismaCloudCompute.Collection.namespaces | String | The Kubernetes namespaces. |
| PrismaCloudCompute.Collection.owner | String | The collection owner \(the last user who modified the collection\). |
| PrismaCloudCompute.Collection.system | Boolean | Whether this collection was created by the system or by the user. |

#### Command Example

```!prisma-cloud-compute-collections-list limit=1```

#### Context Example

```json
{
    "PrismaCloudCompute": {
        "Collection": {
            "functions": [
                "*"
            ], 
            "appIDs": [
                "*"
### prisma-cloud-compute-custom-feeds-ip-add

***
Add a list of banned IP addresses to be blocked by the system.

#### Base Command

`prisma-cloud-compute-custom-feeds-ip-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of custom IP addresses to add to the banned IPs list that will be blocked. For example ip=1.1.1.1,2.2.2.2. | Required | 

#### Context Output

There is no context output for this command.
            "name": "All"
        }
    }
}
```

#### Human Readable Output
>
>### Collections Information
>
>|Name|Description|Owner|Modified|
>|---|---|---|---|
>| All | System - all resources collection | system | September 02, 2021 11:05:06 AM |
### prisma-cloud-compute-custom-feeds-ip-remove

***
Remove a list of IPs from the system's block list.

#### Base Command

`prisma-cloud-compute-custom-feeds-ip-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | A comma-separated list of custom IP addresses to remove from the banned IPs list. For example ip=1.1.1.1,2.2.2.2. | Required | 

#### Context Output

There is no context output for this command.
#### Command Example

```!prisma-cloud-compute-container-namespace-list limit=3```

#### Context Example

```json
{
    "PrismaCloudCompute": {
        "RadarContainerNamespace": [
            "namespace1", 
            "namespace2", 
            "namespace3"
        ]
    }
}
```

#### Human Readable Output
>
>### Collections Information
>
>|Name|
>|---|
>| namespace1 |
>| namespace2 |
>| namespace3 |

### prisma-cloud-compute-images-scan-list

***
Get images scan report. The report includes vulnerabilities, compliance issues, binaries, etc.

#### Base Command

`prisma-cloud-compute-images-scan-list`

#### Requires Role

vulnerabilityManager

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| clusters | A comma-separated list of cluster names to filter the results by. | Optional |
| compact | Whether only minimal image data is to be returned (i.e., skip vulnerabilities, compliance, and extended image metadata). Possible values are: true, false. Default is true. | Optional |
| fields | A comma-separated list of fields to return. Possible values are labels, repo, registry, clusters, hosts, tag. | Optional |
| hostname | A comma-separated list of hostnames to filter the results by. Can be retrieved from !prisma-cloud-compute-profile-host-list. | Optional |
| id | A comma-separated list of image IDs to filter the results by. Run !prisma-cloud-compute-images-scan-list without any arguments to get image IDs. | Optional |
| name | A comma-separated list of image names to filter the results by. | Optional |
| registry | A comma-separated list of image registries to filter the results by. | Optional |
| repository | A comma-separated list of image repositories to filter the results by. | Optional |
| compliance_ids | A comma-separated list of compliance IDs to filter the results by. | Optional |
| limit_record | The maximum number of scan image records to return. Default is 10. | Optional |
| limit_stats | The maximum number of compliance/vulnerability records to return. Default is 10. | Optional |
| offset | The offset by which to begin listing image scan results. Default is 0. | Optional |
| all_results | Whether to retrieve all results. The "limit_record" and "limit_stats" arguments will be ignored. More than 1,500 results will slow down the process. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.ReportsImagesScan._id | String | Image identifier \(image ID or repo:tag\). |
| PrismaCloudCompute.ReportsImagesScan.allCompliance | Unknown | Data regarding passed compliance checks. |
| PrismaCloudCompute.ReportsImagesScan.appEmbedded | Boolean | Whether this image was scanned by an app-embedded defender. |
| PrismaCloudCompute.ReportsImagesScan.applications | Unknown | Products in the image. |
| PrismaCloudCompute.ReportsImagesScan.baseImage | String | The base name of the image. Used when filtering the vulnerabilities by base images. |
| PrismaCloudCompute.ReportsImagesScan.binaries | Unknown | Binaries in the image. |
| PrismaCloudCompute.ReportsImagesScan.cloudMetadata | Unknown | The metadata for an instance running in a cloud provider \(AWS/GCP/Azure\). |
| PrismaCloudCompute.ReportsImagesScan.clusters | String | Cluster names. |
| PrismaCloudCompute.ReportsImagesScan.collections | String | Collections to which this result applies. |
| PrismaCloudCompute.ReportsImagesScan.complianceDistribution | Unknown | The number of vulnerabilities per type. |
| PrismaCloudCompute.ReportsImagesScan.complianceIssues | Unknown | Number of compliance issues. |
| PrismaCloudCompute.ReportsImagesScan.complianceRiskScore | Number | Compliance risk score for the image. |
| PrismaCloudCompute.ReportsImagesScan.creationTime | Date | Date/time when the image was created. |
| PrismaCloudCompute.ReportsImagesScan.distro | String | Full name of the distribution. |
### prisma-cloud-compute-custom-feeds-malware-add

***
Add custom MD5 malware hashes.

#### Base Command

`prisma-cloud-compute-custom-feeds-malware-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name that will be attached to the MD5 records. | Required | 
| md5 | A comma-separated list of MD5 hashes to be added. | Required | 

#### Context Output

There is no context output for this command.
| PrismaCloudCompute.ReportsImagesScan.startupBinaries | Unknown | Binaries that are expected to run when the container is created from this image. |
| PrismaCloudCompute.ReportsImagesScan.tags | Unknown | Tags associated with the given image. |
| PrismaCloudCompute.ReportsImagesScan.topLayer | String | SHA256 of the image's last layer that is the last element of the Layers field. |
| PrismaCloudCompute.ReportsImagesScan.trustResult | Unknown | An aggregated image trust result. |
| PrismaCloudCompute.ReportsImagesScan.trustStatus | String | The trust status for an image. |
| PrismaCloudCompute.ReportsImagesScan.twistlockImage | Boolean | Whether the image is a Twistlock image \(true\) or not \(false\). |
| PrismaCloudCompute.ReportsImagesScan.type | Unknown | The scanning type performed. |
| PrismaCloudCompute.ReportsImagesScan.vulnerabilities | Unknown | CVE vulnerabilities of the image. |
| PrismaCloudCompute.ReportsImagesScan.vulnerabilitiesCount | Number | Total number of vulnerabilities. |
| PrismaCloudCompute.ReportsImagesScan.vulnerabilityDistribution | Unknown | The number of vulnerabilities per type. |
| PrismaCloudCompute.ReportsImagesScan.vulnerabilityRiskScore | Number | Image's CVE risk score. |
| PrismaCloudCompute.ReportsImagesScan.wildFireUsage | Unknown | The Wildfire usage stats. The period for the usage varies with the context. |
| PrismaCloudCompute.ReportsImagesScan.complianceIssuesCount | Number | Number of compliance issues. |
### cve

***
Get information about the CVEs in the system. Will return a maximum of 50 records. It is possible to query for a partial CVE description such as cve-2020 or cve-2014 or by severity/distro/package.

#### Base Command

`cve`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve_id | Deprecated. Use the `cve` argument instead. | Optional | 
| cve | A comma-separated list of CVEs, for example, cve=cve-2016-223,cve-2020-3546. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CVE.ID | String | The ID of the CVE, for example: CVE-2015-1653. | 
| CVE.CVSS | String | The CVSS of the CVE, for example: 10.0. | 
| CVE.Modified | Date | The timestamp of when the CVE was last modified. | 
| CVE.Description | String | A description of the CVE. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 

                "sha256:25f89c88aa30915565de42481044fdc3edcde2edcd88c32098b16adbe09c65ec", 
                "sha256:607e311316ef7ea1437fe4b8f7a6f04f9a61b0f21e2d4ee0611c05bd1d245ff7", 
                "sha256:21511d4e2cf5964090236c3db6aa38c23f8937aab18226dd1898ef4346fa9a3c", 
                "sha256:9ec31cab0619e95e88291cd611370e4d0f61d540862496b89eed00845d48a3a8", 
                "sha256:ce388cb57837216290c2ec5c33ee70ff50ee70a479fdc401f9170f278e68c15d", 
                "sha256:887b26e25244256638869a154e4b7427f124a1ef64723ea7082096025e7f1520", 
                "sha256:40c6aaccab9bea3953dfa459e3426d0f8a23fda23ec5495404ae21afa94af475", 
                "sha256:082ca23ed20f62157e6b3958ed4899fccd6de2501468f668874d746f0af1bc69", 
                "sha256:e252153001780e97deed131418ef8ed0ad8176f55e14916a338120cc8a464af8", 
                "sha256:11f9d19047c7dfc84742694c7c7db04ceb346bf60e44a8a28947937aa3408ba2", 
                "sha256:1945710968a74b7692f635829f9dac189df097b8f7d135aa51f6726dccb2a2be", 
                "sha256:9dfc2f79a6a83bd3791f4b6c621850b49db37ff729cdc17fd0a7b0ec373338c6"
            ], 
            "packages": [
                {
                    "pkgsType": "package", 
                    "pkgs": [
                        {
                            "name": "busybox", 
                            "version": "1.27.2-r8", 
                            "cveCount": 450, 
                            "license": "GPL2", 
                            "layerTime": 1525948365
                        }, 
                        {
                            "name": "apk-tools", 
                            "version": "2.9.1-r2", 
                            "cveCount": 25, 
                            "license": "GPL2", 
                            "layerTime": 1512154128
                        }
                    ]
                }, 
                {
                    "pkgsType": "python", 
                    "pkgs": [
                        {
                            "name": "python", 
                            "version": "2.7.14", 
                            "cveCount": 65, 
                            "license": "PSF license", 
                            "layerTime": 1513722622
                        }, 
                        {
                            "name": "certifi", 
                            "version": "2017.11.5", 
                            "cveCount": 0, 
                            "license": "MPL-2.0", 
                            "layerTime": 1515337812
                        }
                    ]
                }
            ], 
            "complianceDistribution": {
                "high": 1, 
                "total": 1, 
### prisma-cloud-compute-defenders-list

***
Retrieve a list of defenders and their information.

#### Base Command

`prisma-cloud-compute-defenders-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster | The cluster name by which to scope the query. | Optional | 
| hostname | Name of a specific defender to retrieve. | Optional | 
| type | Indicates the defender types to return (e.g., docker, dockerWindows, cri, etc.). | Optional | 
| connected | Indicates whether to return only connected defenders (true) or disconnected defenders (false). Possible values are: true, false. | Optional | 
| limit | The maximum number of defender records to return. Default is 20. | Optional | 
| offset | The offset number by which to begin listing defenders and their information. Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.DefenderDetails.category | String | The category of the defender type \(host/container/serverless\). Range of acceptable values: container, host, serverless, appEmbedded. | 
| PrismaCloudCompute.DefenderDetails.certificateExpiration | Date | The client's certificate expiry time. | 
| PrismaCloudCompute.DefenderDetails.cloudMetadata | Unknown | The cloud provider metadata of the host. | 
| PrismaCloudCompute.DefenderDetails.cluster | String | The provided cluster name. \(Fallback is the internal IP address\). | 
| PrismaCloudCompute.DefenderDetails.clusterID | String | The unique ID generated for each daemon set and used to group defenders by clusters. Note - Kubernetes does not provide a cluster name as part of its API. | 
| PrismaCloudCompute.DefenderDetails.compatibleVersion | Boolean | Whether the defender has a compatible version for communication \(e.g., request logs\). | 
| PrismaCloudCompute.DefenderDetails.connected | Boolean | Whether the defender is connected. | 
| PrismaCloudCompute.DefenderDetails.features | Unknown | The features that are enabled in the defender such as listener type. | 
| PrismaCloudCompute.DefenderDetails.firewallProtection | Unknown | The firewall protection status of the app embedded defenders. | 
| PrismaCloudCompute.DefenderDetails.fqdn | String | The fully qualified domain name used in audit alerts to identify specific hosts. | 
| PrismaCloudCompute.DefenderDetails.hostname | String | The defender hostname. | 
| PrismaCloudCompute.DefenderDetails.lastModified | Date | The last time the defender connectivity was modified. | 
| PrismaCloudCompute.DefenderDetails.port | Number | The communication port between the defender and the console. | 
| PrismaCloudCompute.DefenderDetails.proxy | Unknown | The proxy options of the defender. | 
| PrismaCloudCompute.DefenderDetails.remoteLoggingSupported | Boolean | Whether the defender logs can be retrieved remotely. | 
| PrismaCloudCompute.DefenderDetails.remoteMgmtSupported | Boolean | Whether the defender can be remotely managed \(upgrade, restart\). | 
| PrismaCloudCompute.DefenderDetails.status | Unknown | The feature status of the defender. | 
| PrismaCloudCompute.DefenderDetails.systemInfo | Unknown | The system information of the defender host. | 
| PrismaCloudCompute.DefenderDetails.tasClusterID | String | The ID used to identify the TAS cluster of the defender. Typically will be the cloud controller API address. | 
| PrismaCloudCompute.DefenderDetails.type | String | The type of the defender \(registry scanner/kubernetes node/etc...\). | 
| PrismaCloudCompute.DefenderDetails.version | String | The agent version. | 

            "vulnerabilityRiskScore": 12282000, 
            "history": [
                {
                    "sizeBytes": 4143684, 
                    "instruction": "ADD file:2b00f26f6004576e2f8faeb3fb0517a14f79ea89a059fe096b54cbecf5da512e in / ", 
                    "emptyLayer": false, 
                    "id": "<missing>", 
                    "created": 1512154128
                }, 
                {
                    "instruction": "CMD [\"/bin/sh\"]", 
                    "emptyLayer": true, 
                    "id": "<missing>", 
                    "created": 1512154128
                }
            ]
        }
    }
}
```

#### Human Readable Output
>
>### Image description
>
>|ID|Image|OS Distribution|Vulnerabilities Count|Compliance Issues Count|
>|---|---|---|---|---|
>| image123 | demisto/python:1.3-alpine | Alpine Linux v3.7 | 60 | 1 |
>
>### Vulnerabilities
>
>|Cve|Description|Severity|Package Name|Status|Fix Date|
>|---|---|---|---|---|---|
>| CVE-2018-20679 | An issue was discovered in BusyBox before 1.30.0. An out of bounds read in udhcp components (consumed by the DHCP server, client, and relay) allows a remote attacker to leak sensitive information from the stack by sending a crafted DHCP message. This is related to verification in udhcp_get_option() in networking/udhcp/common.c that 4-byte options are indeed 4 bytes. | high | busybox | fixed in 1.30.1-r5 | January 09, 2019 16:29:00 PM |
>| CVE-2018-1000517 | BusyBox project BusyBox wget version prior to commit 8e2174e9bd836e53c8b9c6e00d1bc6e2a718686e contains a Buffer Overflow vulnerability in Busybox wget that can result in heap buffer overflow. This attack appear to be exploitable via network connectivity. This vulnerability appears to have been fixed in after commit 8e2174e9bd836e53c8b9c6e00d1bc6e2a718686e. | critical | busybox | fixed in 1.29.3-r10 | June 26, 2018 16:29:00 PM |
>
>### Compliances
>
>|Id|Severity|Description|
>|---|---|---|
>| 41 | high | It is a good practice to run the container as a non-root user, if possible. Though user<br>namespace mapping is now available, if a user is already defined in the container image, the<br>container is run as that user by default and specific user namespace remapping is not<br>required |

#### Command Example

```!prisma-cloud-compute-images-scan-list id=image123 limit_stats=2 compact=true```

#### Context Example

```json
{
    "PrismaCloudCompute": {
        "ReportsImagesScan": {
            "cloudMetadata": {
                "resourceID": "i-123", 
                "image": "ami-123", 
                "provider": "aws", 
                "type": "t2.large", 
                "region": "eu-west-123", 
                "accountID": "123"
            }, 
            "hostname": "", 
            "vulnerabilityDistribution": {
                "high": 28, 
                "total": 60, 
                "medium": 20, 
                "critical": 12, 
                "low": 0
            }, 
            "image": {
                "created": "2018-05-10T10:32:49.309Z"
            }, 
            "instances": [
                {
                    "image": "demisto/python:1.3-alpine", 
                    "modified": "2021-12-14T14:19:36.091Z", 
                    "repo": "demisto/python", 
                    "host": "host123", 
                    "tag": "1.3-alpine", 
                    "registry": ""
                }
            ], 
            "complianceIssues": null, 
            "repoTag": {
                "repo": "demisto/python", 
                "tag": "1.3-alpine", 
                "registry": ""
            }, 
            "packageManager": false, 
            "repoDigests": [
                "123"
            ], 
            "id": "image123", 
            "packages": null, 
            "complianceDistribution": {
                "high": 1, 
                "total": 1, 
                "medium": 0, 
                "critical": 0, 
                "low": 0
            }, 
            "firewallProtection": {
                "supported": false, 
                "enabled": false
            }, 
            "allCompliance": {}, 
            "appEmbedded": false, 
            "installedProducts": {
                "docker": "17.06.0-ce", 
                "osDistro": "Alpine Linux v3.7", 
                "hasPackageManager": true
            }, 
            "collections": [
                "All", 
                "123", 
                "Test Collection"
            ], 
            "startupBinaries": null, 
            "scanVersion": "21.04.439", 
            "type": "image", 
            "distro": "Alpine Linux v3.7", 
            "files": null, 
            "scanID": 0, 
            "osDistro": "alpine", 
            "tags": [
                {
                    "repo": "demisto/python", 
                    "tag": "1.3-alpine", 
                    "registry": ""
                }
            ], 
            "Secrets": null, 
            "osDistroRelease": "3.7.0", 
            "topLayer": "sha256:9dfc2f79a6a83bd3791f4b6c621850b49db37ff729cdc17fd0a7b0ec373338c6", 
            "osDistroVersion": "", 
            "trustStatus": "trusted", 
            "firstScanTime": "2021-09-02T11:05:27.439Z", 
            "_id": "image123", 
            "riskFactors": {
                "Remote execution": {}, 
                "High severity": {}, 
                "Has fix": {}, 
                "Attack complexity: low": {}, 
                "Recent vulnerability": {}, 
                "Attack vector: network": {}, 
                "Critical severity": {}, 
                "Medium severity": {}, 
                "DoS": {}
            }, 
            "err": "", 
            "vulnerabilitiesCount": 60, 
            "scanTime": "2021-12-14T14:19:36.091Z", 
            "complianceIssuesCount": 1, 
            "creationTime": "2018-05-10T10:32:49.309Z", 
            "vulnerabilities": null, 
            "hosts": {
                "host123": {
                    "modified": "2021-12-14T14:19:36.091Z"
                }
            }, 
            "complianceRiskScore": 10000, 
            "wildFireUsage": null, 
            "binaries": null, 
            "vulnerabilityRiskScore": 12282000, 
            "history": null
        }
    }
}
```

#### Human Readable Output
>
>### Image description
>
>|ID|Image|OS Distribution|Vulnerabilities Count|Compliance Issues Count|
>|---|---|---|---|---|
>| image123 | demisto/python:1.3-alpine | Alpine Linux v3.7 | 60 | 1 |
>
>### Vulnerability Statistics
>
>|Critical|High|Medium|Low|
>|---|---|---|---|
>| 12 | 28 | 20 | 0 |
>
>### Compliance Statistics
>
>|Critical|High|Medium|Low|
>|---|---|---|---|
>| 0 | 1 | 0 | 0 |

### prisma-cloud-compute-hosts-scan-list

***
Get hosts scan report. The report includes vulnerabilities, compliance issues, binaries, etc.

#### Base Command

`prisma-cloud-compute-hosts-scan-list`

#### Requires Role

vulnerabilityManager

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| clusters | A comma-separated list of cluster names to filter the results by. | Optional |
| compact | Whether only minimal image data is to be returned (i.e., skip vulnerabilities, compliance, and extended image metadata). Possible values are: true, false. Default is true. | Optional |
| distro | A comma-separated list of operating system distros to filter the results by. | Optional |
| fields | A comma-separated list of fields to return. Possible values are labels, repo, registry, clusters, hosts, tag. | Optional |
| hostname | A comma-separated list of hostnames to filter the results by. Can be retrieved from !prisma-cloud-compute-profile-host-list. | Optional |
| provider | A comma-separated list of cloud providers to filter the results by. | Optional |
| compliance_ids | A comma-separated list of compliance IDs to filter the results by. | Optional |
| limit_record | The maximum number of scan host records to return. Default is 10. | Optional |
| limit_stats | The maximum number of compliance/vulnerability records to return. Default is 10. | Optional |
| offset | The offset by which to begin listing host scan results. Default is 0. | Optional |
| all_results | Whether to retrieve all results. The "limit_record" and "limit_stats" arguments will be ignored. More than 1,500 results will slow down the process. Possible values are: true, false. Default is false. | Optional |

#### Context Output
### prisma-cloud-compute-container-namespace-list

***
Get the containers namespaces names.

#### Base Command

`prisma-cloud-compute-container-namespace-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cluster | A comma-separated list of cluster names to filter the results by. | Optional | 
| collections | A comma-separated list of collections to filter the results by. Can be retrieved from the "prisma-cloud-compute-collections-list" command. | Optional | 
| limit | The maximum number of namespace name records to return. Default is 50. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.RadarContainerNamespace | String | The names of the container namespaces. | 

```!prisma-cloud-compute-hosts-scan-list hostname=host123 compact=false limit_stats=2```

#### Context Example

```json
{
    "PrismaCloudCompute": {
        "ReportHostScan": {
            "cloudMetadata": {
                "resourceID": "i-123", 
                "image": "ami-123", 
                "provider": "aws", 
                "type": "t2.large", 
                "region": "eu-west-123", 
                "accountID": "123"
            }, 
            "hostname": "host123", 
            "vulnerabilityDistribution": {
                "high": 4, 
                "total": 191, 
                "medium": 78, 
                "critical": 0, 
                "low": 109
            }, 
            "creationTime": "0001-01-01T00:00:00Z", 
            "image": {
                "created": "0001-01-01T00:00:00Z"
            }, 
            "labels": [
                "osDistro:ubuntu", 
                "osVersion:16.04"
            ], 
### prisma-cloud-compute-images-scan-list

***
Get images scan report. The report includes vulnerabilities, compliance issues, binaries, etc.

#### Base Command

`prisma-cloud-compute-images-scan-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| clusters | A comma-separated list of cluster names to filter the results by. | Optional | 
| compact | Whether only minimal image data is to be returned (i.e., skip vulnerabilities, compliance, and extended image metadata). Possible values are: true, false. Default is true. | Optional | 
| fields | A comma-separated list of fields to return. Possible values are labels, repo, registry, clusters, hosts, tag. | Optional | 
| hostname | A comma-separated list of hostnames to filter the results by. Can be retrieved from the "prisma-cloud-compute-profile-host-list" command. | Optional | 
| id | A comma-separated list of image IDs to filter the results by. Run !prisma-cloud-compute-images-scan-list without any arguments to get image IDs. | Optional | 
| name | A comma-separated list of image names to filter the results by. | Optional | 
| registry | A comma-separated list of image registries to filter the results by. | Optional | 
| repository | A comma-separated list of image repositories to filter the results by. | Optional | 
| compliance_ids | A comma-separated list of compliance IDs to filter the results by. | Optional | 
| limit_record | The maximum number of scan image records to return. Default is 10. | Optional | 
| limit_stats | The maximum number of compliance/vulnerability records to return. Default is 10. | Optional | 
| offset | The offset by which to begin listing image scan results. Default is 0. | Optional | 
| all_results | Whether to retrieve all results. The "limit_record" and "limit_stats" arguments will be ignored. Might slow down the command run time. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.ReportsImagesScan._id | String | Image identifier \(image ID or repo:tag\). | 
| PrismaCloudCompute.ReportsImagesScan.allCompliance | Unknown | Data regarding passed compliance checks. | 
| PrismaCloudCompute.ReportsImagesScan.appEmbedded | Boolean | Whether this image was scanned by an app-embedded defender. | 
| PrismaCloudCompute.ReportsImagesScan.applications | Unknown | Products in the image. | 
| PrismaCloudCompute.ReportsImagesScan.baseImage | String | The base name of the image. Used when filtering the vulnerabilities by base images. | 
| PrismaCloudCompute.ReportsImagesScan.binaries | Unknown | Binaries in the image. | 
| PrismaCloudCompute.ReportsImagesScan.cloudMetadata | Unknown | The metadata for an instance running in a cloud provider \(AWS/GCP/Azure\). | 
| PrismaCloudCompute.ReportsImagesScan.clusters | String | Cluster names. | 
| PrismaCloudCompute.ReportsImagesScan.collections | String | Collections to which this result applies. | 
| PrismaCloudCompute.ReportsImagesScan.complianceDistribution | Unknown | The number of vulnerabilities per type. | 
| PrismaCloudCompute.ReportsImagesScan.complianceIssues | Unknown | Number of compliance issues. | 
| PrismaCloudCompute.ReportsImagesScan.complianceRiskScore | Number | Compliance risk score for the image. | 
| PrismaCloudCompute.ReportsImagesScan.creationTime | Date | Date/time when the image was created. | 
| PrismaCloudCompute.ReportsImagesScan.distro | String | Full name of the distribution. | 
| PrismaCloudCompute.ReportsImagesScan.ecsClusterName | String | Elastic Container Service \(ECS\) cluster name. | 
| PrismaCloudCompute.ReportsImagesScan.err | String | Description of an error that occurred during the image health scan. | 
| PrismaCloudCompute.ReportsImagesScan.externalLabels | Unknown | Kubernetes external labels of all containers running this image. | 
| PrismaCloudCompute.ReportsImagesScan.files | Unknown | Files in the container. | 
| PrismaCloudCompute.ReportsImagesScan.firewallProtection | Unknown | The status of the Web-Application and API Security \(WAAS\) protection. | 
| PrismaCloudCompute.ReportsImagesScan.firstScanTime | Date | Date/time when this image was first scanned \(preserved during version updates\). | 
| PrismaCloudCompute.ReportsImagesScan.history | Unknown | Docker image history. | 
| PrismaCloudCompute.ReportsImagesScan.hostDevices | String | Map from host network device name to IP address. | 
| PrismaCloudCompute.ReportsImagesScan.hostname | String | Name of the host that was scanned. | 
| PrismaCloudCompute.ReportsImagesScan.hosts | Unknown | A fast index for image scan results metadata per host. | 
| PrismaCloudCompute.ReportsImagesScan.id | String | Image ID. | 
| PrismaCloudCompute.ReportsImagesScan.image | Unknown | A container image. | 
| PrismaCloudCompute.ReportsImagesScan.installedProducts | Unknown | Data regarding products running in the environment. | 
| PrismaCloudCompute.ReportsImagesScan.instances | Unknown | Details about each occurrence of the image \(tag \+ host\). | 
| PrismaCloudCompute.ReportsImagesScan.k8sClusterAddr | String | Endpoint of the Kubernetes API server. | 
| PrismaCloudCompute.ReportsImagesScan.labels | String | Image labels. | 
| PrismaCloudCompute.ReportsImagesScan.layers | String | Image's filesystem layers. Each layer is a SHA256 digest of the filesystem diff. | 
| PrismaCloudCompute.ReportsImagesScan.missingDistroVulnCoverage | Boolean | Whether the image operating system is covered in the IS \(true\) or not \(false\). | 
| PrismaCloudCompute.ReportsImagesScan.namespaces | String | Kubernetes namespaces of all the containers running this image. | 
| PrismaCloudCompute.ReportsImagesScan.osDistro | String | Name of the operating system distribution. | 
| PrismaCloudCompute.ReportsImagesScan.osDistroRelease | String | Operating system distribution release. | 
| PrismaCloudCompute.ReportsImagesScan.osDistroVersion | String | Operating system  distribution version. | 
| PrismaCloudCompute.ReportsImagesScan.packageManager | Boolean | Whether the package manager is installed for the operating system. | 
| PrismaCloudCompute.ReportsImagesScan.packages | Unknown | Packages that exist in the image. | 
| PrismaCloudCompute.ReportsImagesScan.registryNamespace | String | IBM cloud namespace to which the image belongs. | 
| PrismaCloudCompute.ReportsImagesScan.repoDigests | String | Digests of the image. Used for content trust \(notary\). Has one digest per tag. | 
| PrismaCloudCompute.ReportsImagesScan.repoTag | Unknown | An image repository and its associated tag or registry digest. | 
| PrismaCloudCompute.ReportsImagesScan.rhelRepos | String | The \(RPM\) repositories IDs from which the packages in this image were installed. Used for matching vulnerabilities by Red Hat CPEs. | 
| PrismaCloudCompute.ReportsImagesScan.riskFactors | Unknown | The mapping of the existence of vulnerability risk factors. | 
| PrismaCloudCompute.ReportsImagesScan.scanID | String | Scan ID. | 
| PrismaCloudCompute.ReportsImagesScan.scanTime | Date | Date/time of the last scan of the image. | 
| PrismaCloudCompute.ReportsImagesScan.scanVersion | String | Defender version that published the image. | 
| PrismaCloudCompute.ReportsImagesScan.startupBinaries | Unknown | Binaries that are expected to run when the container is created from this image. | 
| PrismaCloudCompute.ReportsImagesScan.tags | Unknown | Tags associated with the given image. | 
| PrismaCloudCompute.ReportsImagesScan.topLayer | String | SHA256 of the image's last layer that is the last element of the Layers field. | 
| PrismaCloudCompute.ReportsImagesScan.trustResult | Unknown | An aggregated image trust result. | 
| PrismaCloudCompute.ReportsImagesScan.trustStatus | String | The trust status for an image. | 
| PrismaCloudCompute.ReportsImagesScan.twistlockImage | Boolean | Whether the image is a Twistlock image \(true\) or not \(false\). | 
| PrismaCloudCompute.ReportsImagesScan.type | Unknown | The scanning type performed. | 
| PrismaCloudCompute.ReportsImagesScan.vulnerabilities | Unknown | CVE vulnerabilities of the image. | 
| PrismaCloudCompute.ReportsImagesScan.vulnerabilitiesCount | Number | Total number of vulnerabilities. | 
| PrismaCloudCompute.ReportsImagesScan.vulnerabilityDistribution | Unknown | The number of vulnerabilities per type. | 
| PrismaCloudCompute.ReportsImagesScan.vulnerabilityRiskScore | Number | Image's CVE risk score. | 
| PrismaCloudCompute.ReportsImagesScan.wildFireUsage | Unknown | The Wildfire usage stats. The period for the usage varies with the context. | 
| PrismaCloudCompute.ReportsImagesScan.complianceIssuesCount | Number | Number of compliance issues. | 

| attack_type | The specific policy to update. Possible values are: sqli, xss, cmdi, codeInjection, lfi, attackTools, shellshock, malformedReq, advancedProtectionEffect, intelGathering. | Required |
| action | The new policy action for the attack type. Possible values are: ban, prevent, alert, allow, disable, reCAPTCHA. | Required |
| rule_name | The rule name for the WaaS policy settings. | Required |

#### Context Output

There is no context output for this command.

### Human Readable Output
>
> Successfully updated the WaaS policy

### prisma-cloud-compute-get-audit-firewall-container-alerts

***
Get the audits for the firewall container policies

#### Base Command

`prisma-cloud-compute-get-audit-firewall-container-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ImageName | The image name to get the alerts for. | Required |
| FromDays | The Number of days back to look. | Optional |
| audit_type | The type of audit alert to retrieve. | Required |

#### Context Output

There is no context output for this command.

#### Command example

```!prisma-cloud-compute-get-audit-firewall-container-alerts audit_type=lfi ImageName=`vulnerables/web-dvwa:latest````

#### Human Readable Output

>### Audits
>
>**No entries.**

## Known limitations

When fetching an incident from the Prisma Cloud Compute platform, the platform will delete the fetched incident.
Therefore, it is recommended to configure only one instance per user to fetch incidents.

### prisma-cloud-compute-get-alert-profiles

***
Get the available alert alert profiles from a specific project.

#### Base Command

`prisma-cloud-compute-get-alert-profiles`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| project | The project to get the alert profiles for. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.AlertProfiles.Cortex.Application | String | The alert profile application. |
| PrismaCloudCompute.AlertProfiles.Cortex.CredentialId | String | The credential ID. |
| PrismaCloudCompute.AlertProfiles.Cortex.Enabled | Boolean | Whether the alert profile is enabled. |
| PrismaCloudCompute.AlertProfiles.Cortex.Url | String | The alert profile URL. |
| PrismaCloudCompute.AlertProfiles.Email.CredentialId | String | The alert profile credential ID. |
| PrismaCloudCompute.AlertProfiles.Email.Enabled | Boolean | The email setting for the alert profile. |
| PrismaCloudCompute.AlertProfiles.Email.From | String | The from setting for the email profile. |
| PrismaCloudCompute.AlertProfiles.Email.Port | Number | The email alert profile port. |
| PrismaCloudCompute.AlertProfiles.Email.SmtpAddress | String | The SMTP address. |
| PrismaCloudCompute.AlertProfiles.Email.Ssl | Boolean | The email alert profile SSL. |
| PrismaCloudCompute.AlertProfiles.GcpPubsub.CredentialId | String | The credential ID. |
| PrismaCloudCompute.AlertProfiles.GcpPubsub.Enabled | Boolean | Whether the GCP Pub Sub is enabled. |
| PrismaCloudCompute.AlertProfiles.GcpPubsub.Topic | String | The GCP Pub Sub topic. |
| PrismaCloudCompute.AlertProfiles.Jira.BaseUrl | String | The Jira base URL. |
| PrismaCloudCompute.AlertProfiles.Jira.CaCert | String | The Jira CA Cert. |
| PrismaCloudCompute.AlertProfiles.Jira.CredentialId | String | The Jira credential ID. |
| PrismaCloudCompute.AlertProfiles.Jira.Enabled | Boolean | Jira alert profile status. |
| PrismaCloudCompute.AlertProfiles.Jira.IssueType | String | The Jira issue type. |
| PrismaCloudCompute.AlertProfiles.Jira.Priority | String | The Jira priority. |
| PrismaCloudCompute.AlertProfiles.LastError | String | The last error. |
| PrismaCloudCompute.AlertProfiles.Modified | Date | The modified time. |
| PrismaCloudCompute.AlertProfiles.Name | String | The alert profile name. |
| PrismaCloudCompute.AlertProfiles.Owner | String | The alert profile owner. |
| PrismaCloudCompute.AlertProfiles.Pagerduty.RoutingKey.Encrypted | String | The PagerDuty routing key encryption status. |
| PrismaCloudCompute.AlertProfiles.Pagerduty.Severity | String | The PagerDuty severity. |
| PrismaCloudCompute.AlertProfiles.Pagerduty.Summary | String | The PagerDuty summary. |
| PrismaCloudCompute.AlertProfiles.Policy.Admission.AllRules | Boolean | The policy all rules. |
| PrismaCloudCompute.AlertProfiles.Policy.Admission.Enabled | Boolean | Whether the admission is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.AgentlessAppFirewall.AllRules | Boolean | The agentless app firewall rules. |
| PrismaCloudCompute.AlertProfiles.Policy.AgentlessAppFirewall.Enabled | Boolean | Whether the agentless app firewall is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.AppEmbeddedAppFirewall.AllRules | Boolean | App embedded firewall rules. |
| PrismaCloudCompute.AlertProfiles.Policy.AppEmbeddedAppFirewall.Enabled | Boolean | Whether the app embedded firewall is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.AppEmbeddedRuntime.AllRules | Boolean | App embedded runtime rules. |
| PrismaCloudCompute.AlertProfiles.Policy.AppEmbeddedRuntime.Enabled | Boolean | Whether the app embedded runtime is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.CloudDiscovery.AllRules | Boolean | The cloud discovery rules. |
| PrismaCloudCompute.AlertProfiles.Policy.CloudDiscovery.Enabled | Boolean | Whether the cloud discovery is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.CodeRepoVulnerability.AllRules | Boolean | The code repo vulnerability rules. |
| PrismaCloudCompute.AlertProfiles.Policy.CodeRepoVulnerability.Enabled | Boolean | Whether the code repo vulnerability is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.ContainerAppFirewall.AllRules | Boolean | The container app firewall rules. |
| PrismaCloudCompute.AlertProfiles.Policy.ContainerAppFirewall.Enabled | Boolean | Whether the container app firewall is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.ContainerCompliance.AllRules | Boolean | The container compliance rules. |
| PrismaCloudCompute.AlertProfiles.Policy.ContainerCompliance.Enabled | Boolean | Whether the container compliance is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.ContainerComplianceScan.AllRules | Boolean | The container compliance scan rules. |
| PrismaCloudCompute.AlertProfiles.Policy.ContainerComplianceScan.Enabled | Boolean | Whether the container compliance scan is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.ContainerRuntime.AllRules | Boolean | The container runtime rules. |
| PrismaCloudCompute.AlertProfiles.Policy.ContainerRuntime.Enabled | Boolean | Whether the container runtime is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.ContainerVulnerability.AllRules | Boolean | The container vulnerability rules. |
| PrismaCloudCompute.AlertProfiles.Policy.ContainerVulnerability.Enabled | Boolean | Whether the container vulnerability is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.Defender.AllRules | Boolean | The Defender policy rules. |
| PrismaCloudCompute.AlertProfiles.Policy.Defender.Enabled | Boolean | Whether the Defender policy is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.Docker.AllRules | Boolean | The Docker rules. |
| PrismaCloudCompute.AlertProfiles.Policy.Docker.Enabled | Boolean | Whether the Docker rules are enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.HostAppFirewall.AllRules | Boolean | The app host firewall rules. |
| PrismaCloudCompute.AlertProfiles.Policy.HostAppFirewall.Enabled | Boolean | Whether the host app firewall is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.HostCompliance.AllRules | Boolean | The host compliance rules. |
| PrismaCloudCompute.AlertProfiles.Policy.HostCompliance.Enabled | Boolean | Whether the host compliance is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.HostComplianceScan.AllRules | Boolean | The host compliance scan rules. |
| PrismaCloudCompute.AlertProfiles.Policy.HostComplianceScan.Enabled | Boolean | Whether the host compliance scan is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.HostRuntime.AllRules | Boolean | The host runtime rules. |
| PrismaCloudCompute.AlertProfiles.Policy.HostRuntime.Enabled | Boolean | Whether the host runtime rules are enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.HostVulnerability.AllRules | Boolean | The host vulnerability rules. |
| PrismaCloudCompute.AlertProfiles.Policy.HostVulnerability.Enabled | Boolean | Whether the host vulnerability rule is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.Incident.AllRules | Boolean | The policy incident rules. |
| PrismaCloudCompute.AlertProfiles.Policy.Incident.Enabled | Boolean | Whether the policy incident is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.KubernetesAudit.AllRules | Boolean | The K8S rules. |
| PrismaCloudCompute.AlertProfiles.Policy.KubernetesAudit.Enabled | Boolean | Whether K8S is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.NetworkFirewall.AllRules | Boolean | The network firewall rules. |
| PrismaCloudCompute.AlertProfiles.Policy.NetworkFirewall.Enabled | Boolean | Whether the network firewall rule is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.RegistryVulnerability.AllRules | Boolean | The registry vulnerability rules. |
| PrismaCloudCompute.AlertProfiles.Policy.RegistryVulnerability.Enabled | Boolean | Whether the registry vulnerability rule is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.ServerlessAppFirewall.AllRules | Boolean | The servervless app firewall rules. |
| PrismaCloudCompute.AlertProfiles.Policy.ServerlessAppFirewall.Enabled | Boolean | Whether the serverless app firewall rule is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.ServerlessRuntime.AllRules | Boolean | The serverless runtime rules. |
| PrismaCloudCompute.AlertProfiles.Policy.ServerlessRuntime.Enabled | Boolean | Whether the serverless runtime rule is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.VmCompliance.AllRules | Boolean | The VM compliance rules. |
| PrismaCloudCompute.AlertProfiles.Policy.VmCompliance.Enabled | Boolean | Whether the VM compliance rule is enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.VmVulnerability.AllRules | Boolean | The VM vulnerability rules. |
| PrismaCloudCompute.AlertProfiles.Policy.VmVulnerability.Enabled | Boolean | Whether the VM vulnerability rules are enabled. |
| PrismaCloudCompute.AlertProfiles.Policy.WaasHealth.AllRules | Boolean | The WAAS health rules. |
| PrismaCloudCompute.AlertProfiles.Policy.WaasHealth.Enabled | Boolean | Whether the WAAS health rules are enabled. |
| PrismaCloudCompute.AlertProfiles.PreviousName | String | The alert profile previous name. |
| PrismaCloudCompute.AlertProfiles.SecurityAdvisor.CredentialID | String | The security advisor credential ID. |
| PrismaCloudCompute.AlertProfiles.SecurityAdvisor.Enabled | Boolean | Whether the security advisor is enabled. |
| PrismaCloudCompute.AlertProfiles.SecurityAdvisor.FindingsURL | String | The security advisor findings URL. |
| PrismaCloudCompute.AlertProfiles.SecurityAdvisor.ProviderId | String | The security advisor provider ID. |
| PrismaCloudCompute.AlertProfiles.SecurityAdvisor.TokenURL | String | The security advisor token URL. |
| PrismaCloudCompute.AlertProfiles.SecurityCenter.CredentialId | String | The security center crendential ID. |
| PrismaCloudCompute.AlertProfiles.SecurityCenter.Enabled | Boolean | Whether the security center is enabled. |
| PrismaCloudCompute.AlertProfiles.SecurityCenter.SourceID | String | The security center source ID. |
| PrismaCloudCompute.AlertProfiles.SecurityHub.AccountID | String | The security hub account ID. |
| PrismaCloudCompute.AlertProfiles.SecurityHub.CredentialId | String | The security hub credential ID. |
| PrismaCloudCompute.AlertProfiles.SecurityHub.Enabled | Boolean | Whether the security hub is enabled. |
| PrismaCloudCompute.AlertProfiles.SecurityHub.Region | String | The security hub region. |
| PrismaCloudCompute.AlertProfiles.ServiceNow.Application | String | The ServiceNow application. |
| PrismaCloudCompute.AlertProfiles.ServiceNow.Assignee | String | The ServiceNow assignee. |
| PrismaCloudCompute.AlertProfiles.ServiceNow.CredentialID | String | The ServiceNow credential ID. |
| PrismaCloudCompute.AlertProfiles.ServiceNow.Project | String | The ServiceNow project. |
| PrismaCloudCompute.AlertProfiles.Slack.Enabled | Boolean | Whether the Slack alert profile is enabled. |
| PrismaCloudCompute.AlertProfiles.Slack.WebhookUrl | String | The Slack URL. |
| PrismaCloudCompute.AlertProfiles.Splunk.AuthToken.Encrypted | String | The Splunk auth token. |
| PrismaCloudCompute.AlertProfiles.Splunk.SourceType | String | The Splunk source type. |
| PrismaCloudCompute.AlertProfiles.Splunk.Url | String | The Splunk URL. |
| PrismaCloudCompute.AlertProfiles.VulnerabilityImmediateAlertsEnabled | Boolean | Whether the vulnerability alert is enabled. |
| PrismaCloudCompute.AlertProfiles.Webhook.CredentialId | String | The webhook credential ID. |
| PrismaCloudCompute.AlertProfiles.Webhook.Url | String | The webhook URL. |
| PrismaCloudCompute.AlertProfiles._Id | String | The alert profile ID. |

#### Command example

```!prisma-cloud-compute-get-alert-profiles```

#### Context Example

```json
{
    "PrismaCloudCompute": {
        "AlertProfiles": {
            "Cortex": {
                "Application": "xsoar",
                "CredentialId": "",
                "Enabled": true,
                "Url": ""
            },
            "Email": {
                "CredentialId": "",
                "Enabled": false,
                "From": "",
                "Port": 0,
                "SmtpAddress": "",
                "Ssl": false
            },
            "GcpPubsub": {
                "CredentialId": "",
                "Enabled": false,
                "Topic": ""
            },
            "Jira": {
                "Assignee": {},
                "BaseUrl": "",
                "CaCert": "",
                "CredentialId": "",
                "Enabled": false,
                "IssueType": "",
                "Labels": {},
                "Priority": "",
                "ProjectKey": {}
            },
            "LastError": "",
            "Modified": "2023-04-03T18:43:05.575Z",
            "Name": "XSOAR",
            "Owner": "admin",
            "Pagerduty": {
                "RoutingKey": {
                    "Encrypted": ""
                },
                "Severity": "",
                "Summary": ""
            },
            "Policy": {
                "Admission": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "AgentlessAppFirewall": {
                    "AllRules": true,
                    "Enabled": true,
                    "Rules": []
                },
                "AppEmbeddedAppFirewall": {
                    "AllRules": true,
                    "Enabled": true,
                    "Rules": []
                },
                "AppEmbeddedRuntime": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "CloudDiscovery": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "CodeRepoVulnerability": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "ContainerAppFirewall": {
                    "AllRules": true,
                    "Enabled": true,
                    "Rules": []
                },
                "ContainerCompliance": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "ContainerComplianceScan": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "ContainerRuntime": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "ContainerVulnerability": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "Defender": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "Docker": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "HostAppFirewall": {
                    "AllRules": true,
                    "Enabled": true,
                    "Rules": []
                },
                "HostCompliance": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "HostComplianceScan": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "HostRuntime": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "HostVulnerability": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "Incident": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "KubernetesAudit": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "NetworkFirewall": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "RegistryVulnerability": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "ServerlessAppFirewall": {
                    "AllRules": true,
                    "Enabled": true,
                    "Rules": []
                },
                "ServerlessRuntime": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "VmCompliance": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "VmVulnerability": {
                    "AllRules": true,
                    "Enabled": false,
                    "Rules": []
                },
                "WaasHealth": {
                    "AllRules": true,
                    "Enabled": true,
                    "Rules": []
                }
            },
            "PreviousName": "",
            "SecurityAdvisor": {
                "CredentialID": "",
                "Enabled": false,
                "FindingsURL": "",
                "ProviderId": "",
                "TokenURL": ""
            },
            "SecurityCenter": {
                "CredentialId": "",
                "Enabled": false,
                "SourceID": ""
            },
            "SecurityHub": {
                "AccountID": "",
                "CredentialId": "",
                "Enabled": false,
                "Region": ""
            },
            "ServiceNow": {
                "Application": "",
                "Assignee": "",
                "CredentialID": "",
                "Project": ""
            },
            "Slack": {
                "Enabled": false,
                "WebhookUrl": ""
            },
            "Splunk": {
                "AuthToken": {
                    "Encrypted": ""
                },
                "SourceType": "",
                "Url": ""
            },
            "Sqs": {},
            "VulnerabilityImmediateAlertsEnabled": false,
            "Webhook": {
                "CredentialId": "",
                "Url": ""
            },
            "_Id": "XSOAR"
        }
    }
}
```

#### Human Readable Output

>### Alert Profiles
>
>|admission|agentlessAppFirewall|appEmbeddedAppFirewall|appEmbeddedRuntime|cloudDiscovery|codeRepoVulnerability|containerAppFirewall|containerCompliance|containerComplianceScan|containerRuntime|containerVulnerability|defender|docker|hostAppFirewall|hostCompliance|hostComplianceScan|hostRuntime|hostVulnerability|incident|kubernetesAudit|networkFirewall|registryVulnerability|serverlessAppFirewall|serverlessRuntime|vmCompliance|vmVulnerability|waasHealth|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| enabled: false<br/>allRules: true<br/>rules:  | enabled: true<br/>allRules: true<br/>rules:  | enabled: true<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: true<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: true<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: true<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: false<br/>allRules: true<br/>rules:  | enabled: true<br/>allRules: true<br/>rules:  |

### prisma-cloud-compute-get-settings-defender

***
Get the Defender settings.

#### Base Command

`prisma-cloud-compute-get-settings-defender`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The Defender hostname. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.DefenderSettings.AdmissionControlEnabled | Boolean | The admission control setting. |
| PrismaCloudCompute.DefenderSettings.AdmissionControlWebhookSuffix | String | The webhook suffix. |
| PrismaCloudCompute.DefenderSettings.AppEmbeddedFileSystemTracingEnabled | Boolean | The file tracing setting. |
| PrismaCloudCompute.DefenderSettings.AutomaticUpgrade | Boolean | The automatic upgrade setting. |
| PrismaCloudCompute.DefenderSettings.DisconnectPeriodDays | Number | The disconnect period in days. |
| PrismaCloudCompute.DefenderSettings.HostCustomComplianceEnabled | Boolean | The custom compliance setting. |
| PrismaCloudCompute.DefenderSettings.ListeningPort | Number | The defender listening port. |

#### Command example

```!prisma-cloud-compute-get-settings-defender```

#### Context Example

```json
{
    "PrismaCloudCompute": {
        "DefenderSettings": {
            "AdmissionControlEnabled": false,
            "AdmissionControlWebhookSuffix": "sdgfskdjfbsdkfbsdkjfbsdkfbksdjbf",
            "AppEmbeddedFileSystemTracingEnabled": false,
            "AutomaticUpgrade": false,
            "DisconnectPeriodDays": 1,
            "HostCustomComplianceEnabled": false,
            "ListeningPort": 9998
        }
    }
}
```

#### Human Readable Output

>### Results
>
>|AdmissionControlEnabled|AdmissionControlWebhookSuffix|AppEmbeddedFileSystemTracingEnabled|AutomaticUpgrade|DisconnectPeriodDays|HostCustomComplianceEnabled|ListeningPort|
>|---|---|---|---|---|---|---|
>| false | sdgfskdjfbsdkfbsdkjfbsdkfbksdjbf | false | false | 1 | false | 9998 |

### prisma-cloud-compute-logs-defender

***
Download the Defender logs.

#### Base Command

`prisma-cloud-compute-logs-defender`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The Defender hostname. | Optional |
| lines | The number of log lines to fetch. Default is 10. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.Defenders.Hostname | String | The hostname the log was retrieved from. |
| PrismaCloudCompute.Defenders.Logs.Level | String | The log level. |
| PrismaCloudCompute.Defenders.Logs.Log | String | The log message. |
| PrismaCloudCompute.Defenders.Logs.Time | Date | The time of the log. |
### prisma-cloud-compute-hosts-scan-list

***
Get hosts scan report. The report includes vulnerabilities, compliance issues, binaries, etc.

#### Base Command

`prisma-cloud-compute-hosts-scan-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| clusters | A comma-separated list of cluster names to filter the results by. | Optional | 
| compact | Whether only minimal image data is to be returned (i.e., skip vulnerabilities, compliance, and extended image metadata). Possible values are: true, false. Default is true. | Optional | 
| distro | A comma-separated list of operating system distros to filter the results by. | Optional | 
| fields | A comma-separated list of fields to return. Possible values are labels, repo, registry, clusters, hosts, tag. | Optional | 
| hostname | A comma-separated list of hostnames to filter the results by. Can be retrieved from the "prisma-cloud-compute-profile-host-list" command. | Optional | 
| provider | A comma-separated list of cloud providers to filter the results by. | Optional | 
| compliance_ids | A comma-separated list of compliance IDs to filter the results by. | Optional | 
| limit_record | The maximum number of scan host records to return. Default is 10. | Optional | 
| limit_stats | The maximum number of compliance/vulnerability records to return. Default is 10. | Optional | 
| offset | The offset by which to begin listing host scan results. Default is 0. | Optional | 
| all_results | Whether to retrieve all results. The "limit_record" and "limit_stats" arguments will be ignored. Might slow down the command run time. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.ReportHostScan._id | String | The host identifier \(host ID or hostname\). | 
| PrismaCloudCompute.ReportHostScan.allCompliance | Unknown | The data regarding passed compliance checks. | 
| PrismaCloudCompute.ReportHostScan.appEmbedded | Boolean | Whether this image was scanned by an app-embedded defender. | 
| PrismaCloudCompute.ReportHostScan.applications | Unknown | Products in the image. | 
| PrismaCloudCompute.ReportHostScan.binaries | Unknown | Binaries in the image. | 
| PrismaCloudCompute.ReportHostScan.cloudMetadata | Unknown | The metadata for an instance running in a cloud provider \(AWS/GCP/Azure\). | 
| PrismaCloudCompute.ReportHostScan.clusters | String | Cluster names. | 
| PrismaCloudCompute.ReportHostScan.collections | String | Collections to which this result applies. | 
| PrismaCloudCompute.ReportHostScan.complianceDistribution | Unknown | The number of vulnerabilities per type. | 
| PrismaCloudCompute.ReportHostScan.complianceIssues | Unknown | Number of compliance issues. | 
| PrismaCloudCompute.ReportHostScan.complianceRiskScore | Number | Compliance risk score for the image. | 
| PrismaCloudCompute.ReportHostScan.creationTime | Date | Date/time when the image was created. | 
| PrismaCloudCompute.ReportHostScan.distro | String | Full name of the distribution. | 
| PrismaCloudCompute.ReportHostScan.ecsClusterName | String | Elastic Container Service \(ECS\) cluster name. | 
| PrismaCloudCompute.ReportHostScan.err | String | Description of an error that occurred during image health scan. | 
| PrismaCloudCompute.ReportHostScan.externalLabels | Unknown | Kubernetes external labels of all containers running this image. | 
| PrismaCloudCompute.ReportHostScan.firewallProtection | Unknown | The status of the Web-Application and API Security \(WAAS\) protection. | 
| PrismaCloudCompute.ReportHostScan.firstScanTime | Date | Date/time when this image was first scanned \(preserved during version updates\). | 
| PrismaCloudCompute.ReportHostScan.history | Unknown | Docker image history. | 
| PrismaCloudCompute.ReportHostScan.hostDevices | String | Map from host network device name to IP address. | 
| PrismaCloudCompute.ReportHostScan.hostname | String | Name of the host that was scanned. | 
| PrismaCloudCompute.ReportHostScan.hosts | Unknown | A fast index for image scan results metadata per host. | 
| PrismaCloudCompute.ReportHostScan.image | Unknown | A container image. | 
| PrismaCloudCompute.ReportHostScan.installedProducts | Unknown | Data regarding products running in the environment. | 
| PrismaCloudCompute.ReportHostScan.instances | Unknown | Details about each occurrence of the image \(tag \+ host\). | 
| PrismaCloudCompute.ReportHostScan.k8sClusterAddr | String | Endpoint of the Kubernetes API server. | 
| PrismaCloudCompute.ReportHostScan.namespaces | String | Kubernetes namespaces of all the containers running this image. | 
| PrismaCloudCompute.ReportHostScan.osDistro | String | Name of the operating system distribution. | 
| PrismaCloudCompute.ReportHostScan.osDistroRelease | String | Operating system distribution release. | 
| PrismaCloudCompute.ReportHostScan.osDistroVersion | String | Operating system distribution version. | 
| PrismaCloudCompute.ReportHostScan.packageManager | Boolean | Whether the package manager is installed for the operating system. | 
| PrismaCloudCompute.ReportHostScan.packages | Unknown | The packages that exist in the image. | 
| PrismaCloudCompute.ReportHostScan.repoDigests | String | Digests of the image. Used for content trust \(notary\). Has one digest per tag. | 
| PrismaCloudCompute.ReportHostScan.repoTag | Unknown | An image repository and its associated tag or registry digest. | 
| PrismaCloudCompute.ReportHostScan.riskFactors | Unknown | Maps of the existence of vulnerability risk factors. | 
| PrismaCloudCompute.ReportHostScan.scanID | String | Scan ID. | 
| PrismaCloudCompute.ReportHostScan.scanTime | Date | Date/time of the last scan of the image. | 
| PrismaCloudCompute.ReportHostScan.scanVersion | String | Defender version that published the image. | 
| PrismaCloudCompute.ReportHostScan.startupBinaries | Unknown | Binaries that are expected to run when the container is created from this image. | 
| PrismaCloudCompute.ReportHostScan.tags | Unknown | Tags associated with the given image. | 
| PrismaCloudCompute.ReportHostScan.topLayer | String | SHA256 of the image's last layer that is the last element of the Layers field. | 
| PrismaCloudCompute.ReportHostScan.trustStatus | String | The trust status for an image. | 
| PrismaCloudCompute.ReportHostScan.type | Unknown | The scanning type performed. | 
| PrismaCloudCompute.ReportHostScan.vulnerabilities | Unknown | CVE vulnerabilities of the host. | 
| PrismaCloudCompute.ReportHostScan.vulnerabilitiesCount | Number | Total number of vulnerabilities. | 
| PrismaCloudCompute.ReportHostScan.vulnerabilityDistribution | Unknown | The number of vulnerabilities per type. | 
| PrismaCloudCompute.ReportHostScan.vulnerabilityRiskScore | Number | Image's CVE risk score. | 
| PrismaCloudCompute.ReportHostScan.wildFireUsage | Unknown | The Wildfire usage stats. The period for the usage varies with the context. | 
| PrismaCloudCompute.ReportHostScan.complianceIssuesCount | Unknown | Number of compliance issues. | 

                        }
                    ],
                    "isARM64": false,
                    "labels": [
                        "org.opencontainers.image.ref.name:ubuntu"
                    ],
                    "layers": [
                        "sha256:a5"
                    ],
                    "malwareAnalyzedTime": "0001-01-01T00:00:00Z",
                    "osDistro": "ubuntu",
                    "osDistroRelease": "jammy",
                    "osDistroVersion": "22.04",
                    "packageCorrelationDone": true,
                    "packageManager": true,
                    "pushTime": "0001-01-01T00:00:00Z",
                    "redHatNonRPMImage": false,
                    "repoDigests": [],
                    "repoTag": {
                        "registry": "1.dkr.ecr.eu-central-1.amazonaws.com",
                        "repo": "pythonscript",
                        "tag": "tag"
                    },
                    "riskFactors": {
                        "Attack complexity: low": {},
                        "Attack vector: network": {},
                        "Critical severity": {},
                        "DoS - High": {},
                        "DoS - Low": {},
                        "Exploit exists - POC": {},
                        "Has fix": {},
                        "High severity": {},
                        "Medium severity": {},
                        "Recent vulnerability": {},
                        "Remote execution": {}
                    },
                    "scanBuildDate": "20230914",
                    "scanID": 0,
                    "scanTime": "2023-09-20T12:53:36.956Z",
                    "scanVersion": "31.01.131",
                    "secretScanMetrics": {},
                    "tags": [
                        {
                            "registry": "1.dkr.ecr.eu-central-1.amazonaws.com",
                            "repo": "pythonscript",
                            "tag": "tag"
                        }
                    ],
                    "topLayer": "sha256:a6",
                    "trustStatus": "",
                    "type": "ciImage",
                    "vulnerabilitiesCount": 81,
                    "vulnerabilityDistribution": {
                        "critical": 1,
                        "high": 5,
                        "low": 34,
                        "medium": 41,
                        "total": 81
                    },
                    "vulnerabilityRiskScore": 1054134,
                    "wildFireUsage": null
                },
                "pass": true,
                "time": "2023-09-20T12:53:37.229Z",
                "version": "30.01.1"
            },
            {
                "_id": "bbb",
                "entityInfo": {
                    "Secrets": [
                        "/opt/aa/lib/python3.10/test/secret.pem"
                    ],
                    "_id": "sha256:f3",
                    "agentless": false,
                    "allCompliance": {},
                    "appEmbedded": false,
                    "applications": [
                        {
                            "installedFromPackage": true,
                            "knownVulnerabilities": 115,
                            "layerTime": 1695209203,
                            "name": "ccc",
                            "path": "/usr/bin/node",
                            "version": "12.01.01"
                        }
                    ],
                    "cloudMetadata": {},
                    "collections": [
                        "Access Group"
                    ],
                    "complianceDistribution": {
                        "critical": 0,
                        "high": 4,
                        "low": 0,
                        "medium": 1,
                        "total": 5
                    },
                    "complianceIssuesCount": 5,
                    "complianceRiskScore": 40100,
                    "creationTime": "2023-09-20T11:27:10.233Z",
                    "distro": "Ubuntu 22.04.3 LTS",
                    "err": "",
                    "files": [],
                    "firewallProtection": {
                        "enabled": false,
                        "outOfBandMode": "",
                        "supported": false
                    },
                    "firstScanTime": "2023-09-20T11:27:22.081Z",
                    "foundSecrets": null,
                    "hostname": "aaa",
                    "hosts": {},
                    "id": "sha256:a1",
                    "image": {
                        "created": "2023-09-20T11:27:10.233Z",
                        "entrypoint": [
                            "python3"
                        ]
                    },
                    "installedProducts": {
                        "docker": "24.0.6",
                        "hasPackageManager": true,
                        "osDistro": "Ubuntu 22.04.3 LTS"
                    },
                    "instances": [
                        {
                            "host": "aaa",
                            "image": "pythonserver.azurecr.io/pythonserver:a1",
                            "modified": "2023-09-20T11:27:50.809Z",
                            "registry": "pythonserver.azurecr.io",
                            "repo": "pythonserver",
                            "tag": "a1"
                        }
                    ],
                    "isARM64": false,
                    "labels": [
                        "org.opencontainers.image.ref.name:ubuntu",
                        "org.opencontainers.image.version:22.04"
                    ],
                    "layers": [
                        "sha256:a1"
                    ],
                    "malwareAnalyzedTime": "0001-01-01T00:00:00Z",
                    "osDistro": "ubuntu",
                    "osDistroRelease": "jammy",
                    "osDistroVersion": "22.04",
                    "packageCorrelationDone": true,
                    "packageManager": true,
                    "pushTime": "0001-01-01T00:00:00Z",
                    "redHatNonRPMImage": false,
                    "repoDigests": [],
                    "repoTag": {
                        "registry": "pythonserver.azurecr.io",
                        "repo": "pythonserver",
                        "tag": "tag"
                    },
                    "riskFactors": {
                        "Attack complexity: low": {},
                        "Attack vector: network": {},
                        "Critical severity": {},
                        "DoS - High": {},
                        "DoS - Low": {},
                        "Exploit exists - POC": {},
                        "Has fix": {},
                        "High severity": {},
                        "Medium severity": {},
                        "Recent vulnerability": {},
                        "Remote execution": {}
                    },
                    "scanBuildDate": "20230914",
                    "scanID": 0,
                    "scanTime": "2023-09-20T11:27:50.809Z",
                    "scanVersion": "31.01.131",
                    "secretScanMetrics": {},
                    "tags": [
                        {
                            "registry": "pythonserver.azurecr.io",
                            "repo": "pythonserver",
                            "tag": "tag"
                        }
                    ],
                    "topLayer": "sha256:a6",
                    "trustStatus": "",
                    "type": "ciImage",
                    "vulnerabilitiesCount": 72,
                    "vulnerabilityDistribution": {
                        "critical": 1,
                        "high": 5,
                        "low": 34,
                        "medium": 32,
                        "total": 72
                    },
                    "vulnerabilityRiskScore": 1053234,
                    "wildFireUsage": null
                },
                "pass": true,
                "time": "2023-09-20T11:27:51.087Z",
                "version": "31.01.131"
            }
        ]
    }
}
```

#### Human Readable Output

>### CI Scan Information
>
>|Image|ID|OS Distribution|OS Release|Scan Status|Scan Time|
>|---|---|---|---|---|---|
>| 1.dkr.ecr.eu-central-1.amazonaws.com/pythonscript:tag | sha256:a6 | ubuntu | jammy | true | 2023-09-20T12:53:37.229Z |
>| pythonserver.azurecr.io/pythonserver:a1 | sha256:a5 | ubuntu | jammy | true | 2023-09-20T11:27:51.087Z |

### prisma-cloud-compute-trusted-images-list

***
Returns the trusted registries, repositories, and images. Maps to the image table in Defend > Compliance > Trusted Images in the Console UI.

#### Base Command

`prisma-cloud-compute-trusted-images-list`

#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.TrustedImage.policy.enabled | Boolean | Whether the trusted image policy is enabled. |
| PrismaCloudCompute.TrustedImage.policy._id | String | The ID of the trusted image policy. |
| PrismaCloudCompute.TrustedImage.policy.rules.name | String | The name of the trusted image rule. |
| PrismaCloudCompute.TrustedImage.policy.rules.allowedGroups | Unknown | The allowed groups for the trusted image rule. |
| PrismaCloudCompute.TrustedImage.policy.rules.effect | String | The effect of the trusted image rule. |
| PrismaCloudCompute.TrustedImage.policy.rules.modified | Date | The last modified timestamp for the trusted image rule. |
| PrismaCloudCompute.TrustedImage.policy.rules.previousName | String | The previous name of the trusted image rule. |
| PrismaCloudCompute.TrustedImage.policy.rules.owner | String | The owner of the trusted image rule. |
| PrismaCloudCompute.TrustedImage.policy.rules.disabled | Boolean | Whether the trusted image rule is disabled. |
| PrismaCloudCompute.TrustedImage.policy.rules.collections | Unknown | The collections for the trusted image rule. |
| PrismaCloudCompute.TrustedImage.groups.modified | Date | The last modified timestamp for the trusted image group. |
| PrismaCloudCompute.TrustedImage.groups.owner | String | The owner of the trusted image group. |
| PrismaCloudCompute.TrustedImage.groups.name | String | The name of the trusted image group. |
| PrismaCloudCompute.TrustedImage.groups.previousName | String | The previous name of the trusted image group. |
| PrismaCloudCompute.TrustedImage.groups._id | String | The ID of the trusted image group. |
| PrismaCloudCompute.TrustedImage.groups.images | Unknown | The images in the trusted image group. |

#### Command example

```!prisma-cloud-compute-trusted-images-list```

#### Context Example

```json
{
    "PrismaCloudCompute": {
        "TrustedImage": {
            "groups": [
                {
                    "_id": "Deny All",
                    "images": [
                        "*gg/*"
                    ],
                    "modified": "2022-04-27T17:30:02.803Z",
                    "name": "",
                    "owner": "test@paloaltonetworks.com",
                    "previousName": ""
                },
                {
                    "_id": "TRUSTED IMAGES",
                    "images": [
                        "img/aa:*",
                        "img/bb:*"
                    ],
                    "modified": "2023-02-27T21:35:49.697Z",
                    "name": "",
                    "owner": "test@paloaltonetworks.com",
                    "previousName": ""
                },
                {
                    "_id": "test",
                    "images": [
                        "img/abc:*"
                    ],
                    "modified": "2023-02-28T19:53:44.491Z",
                    "name": "",
                    "owner": "test@paloaltonetworks.com",
                    "previousName": ""
                }
            ],
            "policy": {
                "_id": "trust",
                "enabled": true,
                "rules": [
                    {
                        "allowedGroups": [
                            "test"
                        ],
                        "collections": [
                            {
                                "accountIDs": [
                                    "*"
                                ],
                                "appIDs": [
                                    "*"
                                ],
                                "clusters": [
                                    "*"
                                ],
                                "codeRepos": [
                                    "*"
                                ],
                                "color": "#3FA2F7",
                                "containers": [
                                    "*"
                                ],
                                "description": "System - all resources collection",
                                "functions": [
                                    "*"
                                ],
                                "hosts": [
                                    "*"
                                ],
                                "images": [
                                    "*"
                                ],
                                "labels": [
                                    "*"
                                ],
                                "modified": "2021-01-31T08:21:54.823Z",
                                "name": "All",
                                "namespaces": [
                                    "*"
                                ],
                                "owner": "system",
                                "prisma": false,
                                "system": true
                            }
                        ],
                        "disabled": true,
                        "effect": "alert",
                        "modified": "2023-06-08T12:28:46.723Z",
                        "name": "test",
                        "owner": "test@paloaltonetworks.com",
                        "previousName": ""
                    },
                    {
                        "collections": [
                            {
                                "accountIDs": [
                                    "*"
                                ],
                                "appIDs": [
                                    "*"
                                ],
                                "clusters": [
                                    "*"
                                ],
                                "codeRepos": [
                                    "*"
                                ],
                                "color": "#3FA2F7",
                                "containers": [
                                    "*"
                                ],
                                "description": "System - all resources collection",
                                "functions": [
                                    "*"
                                ],
                                "hosts": [
                                    "*"
                                ],
                                "images": [
                                    "*"
                                ],
                                "labels": [
                                    "*"
                                ],
                                "modified": "2021-01-31T08:21:54.823Z",
                                "name": "All",
                                "namespaces": [
                                    "*"
                                ],
                                "owner": "system",
                                "prisma": false,
                                "system": true
                            }
                        ],
                        "disabled": true,
                        "effect": "alert",
                        "modified": "2022-04-27T19:24:00.987Z",
                        "name": "Default - alert all",
                        "owner": "test@paloaltonetworks.com",
                        "previousName": ""
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>## Trusted Images Details
>
>### Policy Rules Information
>
>|Rule Name|Effect|Owner|Allowed Groups|Modified|
>|---|---|---|---|---|
>| test | alert | test@paloaltonetworks.com | test | 2023-06-08T12:28:46.723Z |
>| Default - alert all | alert | test@paloaltonetworks.com |  | 2022-04-27T19:24:00.987Z |
>
>### Trust Groups Information
>
>|ID|Owner|Modified|
>|---|---|---|
>| Deny All | test@paloaltonetworks.com | 2022-04-27T17:30:02.803Z |
>| TRUSTED IMAGES | test@paloaltonetworks.com | 2023-02-27T21:35:49.697Z |
>| test | test@paloaltonetworks.com | 2023-02-28T19:53:44.491Z |

### prisma-cloud-compute-trusted-images-update

***
Updates a trusted image to the system. Specify trusted images using either the image name or layers properties. This is a potentially harmful command, so use with caution.

#### Base Command

`prisma-cloud-compute-trusted-images-update`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| images_list_json | JSON containing the list of trusted images to update. In order to view the structure, use ***prisma-cloud-compute-trusted-images-list*** to retrieve the current state of the list. | Required |

#### Context Output

There is no context output for this command.

### prisma-cloud-compute-vulnerabilities-impacted-resources-list

***
Get the list of Prisma Cloud Compute vulnerabilities resources.

#### Base Command

`prisma-cloud-compute-vulnerabilities-impacted-resources-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| cve | A comma-separated list of CVE IDs that can be used as a pivot for the impacted resource search. For example cve=CVE-2018-14600,CVE-2021-31535. | Optional | 
| limit | The maximum number of records of impacted hosts/images to return. Default is 50. | Optional | 
| offset | The offset by which to begin listing impacted hosts/images records. Default is 0. | Optional | 
| resourceType | ResourceType is the single resource type to return vulnerability data for. Possible values are: container, image, host, function, codeRepo, registryImage. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.VulnerabilitiesImpactedResource._id | String | Id is the CVE ID \(index for the impacted resources\). | 
| PrismaCloudCompute.VulnerabilitiesImpactedResource.codeRepos | Array | CodeRepos is a list of impacted code repositories. | 
| PrismaCloudCompute.VulnerabilitiesImpactedResource.codeReposCount | integer | CodeReposCount is the total impacted code repositories count. | 
| PrismaCloudCompute.VulnerabilitiesImpactedResource.functions | Array | Functions is a map between function id to its details. | 
| PrismaCloudCompute.VulnerabilitiesImpactedResource.functionsCount | integer | FunctionsCount is the total impacted functions count. | 
| PrismaCloudCompute.VulnerabilitiesImpactedResource.hosts | Array | Hosts is the list of impacted hosts. | 
| PrismaCloudCompute.VulnerabilitiesImpactedResource.hostsCount | integer | HostsCount is the total impacted hosts count. | 
| PrismaCloudCompute.VulnerabilitiesImpactedResource.images | Array | Images is the list of impacted hosts. | 
| PrismaCloudCompute.VulnerabilitiesImpactedResource.imagesCount | integer | ImagesCount is the total impacted images count. | 
| PrismaCloudCompute.VulnerabilitiesImpactedResource.registryImages | Array | RegistryImages is a list of impacted registry images. | 
| PrismaCloudCompute.VulnerabilitiesImpactedResource.registryImagesCount | integer | RegistryImagesCount is the total impacted registry images count. | 

                        "total": 12
                    },
                    "complianceIssues": [
                        {
                            "cause": "",
                            "cri": false,
                            "cve": "",
                            "cvss": 0,
                            "description": "Process ID (PID) namespaces isolate the process ID number space",
                            "discovered": "0001-01-01T00:00:00Z",
                            "exploit": "",
                            "fixDate": 0,
                            "functionLayer": "",
                            "id": 515,
                            "layerTime": 0,
                            "link": "",
                            "packageName": "",
                            "packageVersion": "",
                            "published": 0,
                            "riskFactors": null,
                            "secret": {},
                            "severity": "critical",
                            "status": "",
                            "templates": [
                                "GGG"
                            ],
                            "text": "",
                            "title": "Do not share the process namespace",
                            "twistlock": false,
                            "type": "container",
                            "vecStr": "",
                            "wildfireMalware": {}
                        }
                    ],
                    "complianceIssuesCount": 12,
                    "complianceRiskScore": 7050000,
                    "id": "a4",
                    "image": "img3",
                    "imageID": "sha256:a5",
                    "imageName": "img5",
                    "infra": false,
                    "installedProducts": {
                        "crio": true
                    },
                    "labels": [
                        "aa"
                    ],
                    "name": "a7",
                    "namespace": "system",
                    "network": {
                        "ports": []
                    },
                    "processes": [
                        {
                            "name": "a7"
                        }
                    ],
                    "profileID": "sha256:a3",
                    "startTime": "2023-09-10T01:46:16.542Z"
                },
                "scanTime": "2023-09-26T01:46:44.579Z"
            },
            {
                "_id": "a2",
                "agentless": true,
                "agentlessScanID": 476,
                "collections": [
                    "All"
                ],
                "csa": false,
                "firewallProtection": {
                    "enabled": false,
                    "outOfBandMode": "",
                    "supported": false
                },
                "hostname": "hostname",
                "info": {
                    "allCompliance": {},
                    "app": "app9",
                    "cloudMetadata": {
                        "accountID": "66",
                        "image": "img7",
                        "name": "a5-master",
                        "provider": "aws",
                        "region": "eu-south-1",
                        "resourceID": "i-3",
                        "type": "m5.xlarge"
                    },
                    "cluster": "a5",
                    "clusterType": "",
                    "complianceDistribution": {
                        "critical": 7,
                        "high": 5,
                        "low": 0,
                        "medium": 0,
                        "total": 12
                    },
                    "complianceIssues": [
                        {
                            "cause": "",
                            "cri": true,
                            "cve": "",
                            "cvss": 0,
                            "description": "The main container's host has full access to its network interfaces",
                            "discovered": "0001-01-01T00:00:00Z",
                            "exploit": "",
                            "fixDate": 0,
                            "functionLayer": "",
                            "id": 5059,
                            "layerTime": 0,
                            "link": "",
                            "packageName": "",
                            "packageVersion": "",
                            "published": 0,
                            "riskFactors": null,
                            "secret": {},
                            "severity": "critical",
                            "status": "",
                            "templates": null,
                            "text": "",
                            "title": "Do not share the host's network namespace",
                            "twistlock": false,
                            "type": "container",
                            "vecStr": "",
                            "wildfireMalware": {}
                        }
                    ],
                    "complianceIssuesCount": 12,
                    "complianceRiskScore": 7050000,
                    "id": "a5",
                    "image": "a7",
                    "imageID": "a9",
                    "imageName": "a7",
                    "infra": false,
                    "installedProducts": {
                        "crio": true
                    },
                    "labels": [
                        "tag"
                    ],
                    "name": "aaa",
                    "namespace": "test",
                    "network": {
                        "ports": []
                    },
                    "processes": [],
                    "profileID": "a9_test_a5",
                    "startTime": "2022-09-14T09:07:18.502Z"
                },
                "scanTime": "2023-09-26T00:20:45.054Z"
            }
        ]
    }
}
```

#### Human Readable Output

>### CI Scan Information
>
>|ID|Hostname|Scan Time|Image ID|Image Name|Name|App|
>|---|---|---|---|---|---|---|
>| a1 | a1 | 2023-09-26T01:46:44.579Z | sha256:a1 | img5 | hhh | a2 |
>| a5 | hostname | 2023-09-26T00:20:45.054Z | a9 | a7 | a9 | test |

### prisma-cloud-compute-hosts-list
### prisma-cloud-compute-get-audit-firewall-container-alerts

***
Get the audits for the firewall container policies.

#### Base Command

`prisma-cloud-compute-get-audit-firewall-container-alerts`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ImageName | The image name to get the alerts for. | Required | 
| FromDays | The Number of days back to look. | Optional | 
| audit_type | The type of audit alert to retrieve. | Required | 
| limit | The limit of the number of alerts to return. | Optional | 

#### Context Output

There is no context output for this command.
| PrismaCloudCompute.Hosts.distro | String | The host distribution. |
| PrismaCloudCompute.Hosts.foundSecrets | Boolean | Whether secrets were found. |
| PrismaCloudCompute.Hosts.vulnerabilitiesCount | Number | Number of vulnerabilities found. |
| PrismaCloudCompute.Hosts.complianceIssuesCount | Number | Number of compliance issues found. |
| PrismaCloudCompute.Hosts.vulnerabilityRiskScore | Number | The host's vulnerability risk score. |
| PrismaCloudCompute.Hosts.complianceRiskScore | Number | The host's compliance risk score. |
| PrismaCloudCompute.Hosts.riskFactors | Unknown | Risk factors for the host. |
| PrismaCloudCompute.Hosts.collections | Unknown | The collections the host belongs to. |
| PrismaCloudCompute.Hosts.agentless | Boolean | Whether the host was scanned agentlessly. |

#### Command example

```!prisma-cloud-compute-hosts-list limit=2```

#### Context Example

```json
{
    "PrismaCloudCompute": {
        "Hosts": [
            {
                "Secrets": null,
                "_id": "a9",
                "agentless": false,
                "allCompliance": {},
                "appEmbedded": false,
                "binaries": null,
                "cloudMetadata": {},
                "collections": [
                    "All"
                ],
                "complianceDistribution": {
                    "critical": 0,
                    "high": 0,
                    "low": 0,
                    "medium": 0,
                    "total": 0
                },
                "complianceIssues": null,
                "complianceIssuesCount": 0,
                "complianceRiskScore": 0,
                "creationTime": "0001-01-01T00:00:00Z",
                "distro": "Ubuntu 20.04.4 LTS",
                "err": "",
                "files": null,
                "firewallProtection": {
                    "enabled": false,
                    "outOfBandMode": "",
                    "supported": false
                },
                "firstScanTime": "0001-01-01T00:00:00Z",
                "foundSecrets": null,
                "history": null,
                "hostname": "a9",
                "hosts": null,
                "image": {
                    "created": "0001-01-01T00:00:00Z"
                },
                "installedProducts": {},
                "instances": null,
                "isARM64": false,
                "malwareAnalyzedTime": "0001-01-01T00:00:00Z",
                "osDistro": "",
                "osDistroRelease": "focal",
                "osDistroVersion": "",
                "packageCorrelationDone": false,
                "packageManager": false,
                "packages": null,
                "pushTime": "0001-01-01T00:00:00Z",
                "redHatNonRPMImage": false,
                "repoDigests": null,
                "repoTag": null,
                "riskFactors": null,
                "scanID": 0,
                "scanTime": "0001-01-01T00:00:00Z",
                "secretScanMetrics": {},
                "startupBinaries": null,
                "tags": null,
                "trustStatus": "",
                "type": "",
                "vulnerabilities": null,
                "vulnerabilitiesCount": 0,
                "vulnerabilityDistribution": {
                    "critical": 0,
                    "high": 0,
                    "low": 0,
                    "medium": 0,
                    "total": 0
                },
                "vulnerabilityRiskScore": 0,
                "wildFireUsage": null
            },
            {
                "Secrets": null,
                "_id": "a4",
                "agentless": false,
                "allCompliance": {},
                "appEmbedded": false,
                "binaries": null,
                "cloudMetadata": {},
                "collections": [
                    "All"
                ],
                "complianceDistribution": {
                    "critical": 0,
                    "high": 0,
                    "low": 0,
                    "medium": 0,
                    "total": 0
                },
                "complianceIssues": null,
                "complianceIssuesCount": 0,
                "complianceRiskScore": 0,
                "creationTime": "0001-01-01T00:00:00Z",
                "distro": "Ubuntu 20.04.4 LTS",
                "err": "",
                "files": null,
                "firewallProtection": {
                    "enabled": false,
                    "outOfBandMode": "",
                    "supported": false
                },
                "firstScanTime": "0001-01-01T00:00:00Z",
                "foundSecrets": null,
                "history": null,
                "hostname": "hostname3",
                "hosts": null,
                "image": {
                    "created": "0001-01-01T00:00:00Z"
                },
                "installedProducts": {},
                "instances": null,
                "isARM64": false,
                "malwareAnalyzedTime": "0001-01-01T00:00:00Z",
                "osDistro": "",
                "osDistroRelease": "focal",
                "osDistroVersion": "",
                "packageCorrelationDone": false,
                "packageManager": false,
                "packages": null,
                "pushTime": "0001-01-01T00:00:00Z",
                "redHatNonRPMImage": false,
                "repoDigests": null,
                "repoTag": null,
                "riskFactors": null,
                "scanID": 0,
                "scanTime": "0001-01-01T00:00:00Z",
                "secretScanMetrics": {},
                "startupBinaries": null,
                "tags": null,
                "trustStatus": "",
                "type": "",
                "vulnerabilities": null,
                "vulnerabilitiesCount": 0,
                "vulnerabilityDistribution": {
                    "critical": 0,
                    "high": 0,
                    "low": 0,
                    "medium": 0,
                    "total": 0
                },
                "vulnerabilityRiskScore": 0,
                "wildFireUsage": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Hosts Information
>
>|ID|Hostname|Scan Time|Distro|Distro Release|
>|---|---|---|---|---|
>| a9 | a9 | 0001-01-01T00:00:00Z | Ubuntu 20.04.4 LTS | focal |
>| a4 | hostname1 | 0001-01-01T00:00:00Z | Ubuntu 20.04.4 LTS | focal |

### prisma-cloud-compute-runtime-container-audit-events-list

***
Retrieves all container audit events when a runtime sensor such as process, network, file system, or system call detects an activity that deviates from the predictive model.

#### Base Command

`prisma-cloud-compute-runtime-container-audit-events-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collections | A comma-separated list of collection names that you have defined in Prisma Cloud Compute. | Optional |
| account_ids | A comma-separated list of cloud account IDs. | Optional |
| clusters | A comma-separated list of cluster names. | Optional |
| namespaces | A comma-separated list of namespace names. | Optional |
| resource_ids | A comma-separated list of resource IDs. | Optional |
| region | A comma-separated list of cloud region names. | Optional |
| audit_id | A comma-separated list of audit event IDs. | Optional |
| profile_id | A comma-separated list of runtime profile IDs. | Optional |
| image_name | A comma-separated list of image names. | Optional |
| container | A comma-separated list of container names. | Optional |
| container_id | A comma-separated list of container IDs. | Optional |
| type | A comma-separated list of audit event types. | Optional |
| effect | A comma-separated list of audit event effects. | Optional |
| user | A comma-separated list of users. | Optional |
| os | A comma-separated list of operating systems. | Optional |
| app | A comma-separated list of applications. | Optional |
| hostname | A comma-separated list of hostnames. | Optional |
| search | Term to search for. | Optional |
| limit | The maximum number of container scan reports to return. Must be between 1-50. Default is 50. | Optional |
| offset | The offset by which to begin listing container scan reports. Default is 0. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.RuntimeContainerAuditEvents.os | String | The operating system of the container. |
| PrismaCloudCompute.RuntimeContainerAuditEvents._id | String | The audit event ID. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.time | Date | The audit event time. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.hostname | String | The hostname. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.fqdn | String | The audited event container's fully qualified domain name. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.user | String | The audited event user. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.type | String | The audit event type. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.containerId | String | The container ID. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.containerName | String | The container name. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.imageName | String | The image name. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.imageId | String | The image ID. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.namespace | String | The namespace. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.effect | String | The audit event effect. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.ruleName | String | The rule name. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.msg | String | The audit event message. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.profileId | String | The profile ID. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.pid | Number | The process ID. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.processPath | String | The process path. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.collections | Unknown | The collections. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.attackType | String | The attack type. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.count | Number | The count of audit events. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.container | Boolean | Whether the audit event was from a container. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.severity | String | The severity of the audit event. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.region | String | The region of the container. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.accountID | String | The account ID of the container. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.cluster | String | The cluster of the container. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.filepath | String | The file path of the audit event. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.md5 | String | The MD5 hash of the file. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.command | String | The command of the audit event. |
| PrismaCloudCompute.RuntimeContainerAuditEvents.provider | String | The provider of the container. |

#### Command example

```!prisma-cloud-compute-runtime-container-audit-events-list limit=2```

#### Context Example

```json
{
    "PrismaCloudCompute": {
        "RuntimeContainerAuditEvents": [
            {
                "_id": "a9",
                "accountID": "11",
                "attackType": "malwareFileFeed",
                "cluster": "pc-demo-eks-ii",
                "collections": [
                    "All"
                ],
                "command": "cmd",
                "container": true,
                "containerId": "c2",
                "containerName": "python-server-app",
                "count": 1,
                "effect": "block",
                "filepath": "f5",
                "fqdn": "",
                "hostname": "hostname4",
                "imageId": "sha256:r4",
                "imageName": "r6",
                "md5": "r8",
                "msg": "msg6",
                "namespace": "default",
                "os": "Ubuntu 22.04.2 LTS",
                "pid": 6283,
                "processPath": "/usr/bin/git",
                "profileId": "sha256:r4_default_pc-demo-eks-ii",
                "provider": "aws",
                "region": "eu-central-1",
                "ruleName": "ii-pc-advanced-demo-eks-block",
                "severity": "high",
                "time": "2023-08-20T12:44:45.128Z",
                "type": "filesystem",
                "user": "root"
            },
            {
                "_id": "b5",
                "accountID": "s4",
                "attackType": "malwareFileFeed",
                "cluster": "pc-github",
                "collections": [
                    "All"
                ],
                "command": "cmd",
                "container": true,
                "containerId": "t6",
                "containerName": "na6",
                "count": 1,
                "effect": "block",
                "filepath": "f5",
                "fqdn": "",
                "hostname": "n7",
                "imageId": "sha256:n6",
                "imageName": "img6",
                "md5": "r8",
                "msg": "msg6",
                "namespace": "default",
                "os": "Ubuntu 22.04.3 LTS",
                "pid": 25597,
                "processPath": "/usr/bin/git",
                "profileId": "sha256:n6_default_pc-github",
                "provider": "aws",
                "region": "us-east-2",
                "ruleName": "ii-pc-advanced-demo-eks-block",
                "severity": "high",
                "time": "2023-08-20T12:45:45.405Z",
                "type": "filesystem",
                "user": "root"
            }
        ]
    }
}
```

#### Human Readable Output

>### Runtime Container Audit Events Information
>
>|ID|Hostname|Container Name|Image Name|Effect|Type|Attack Type|Severity|
>|---|---|---|---|---|---|---|---|
>| a9 | hostname4 | python-server-app | r6 | block | filesystem | malwareFileFeed | high |
>| b5 | n7 | na6 | img6 | block | filesystem | malwareFileFeed | high |

### prisma-cloud-compute-archive-audit-incident

***
Acknowledges an incident and moves it to an archived state.

#### Base Command

`prisma-cloud-compute-archive-audit-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID. | Required |
| action | Action for the command. archive - incident will be archived, unarchive - incident will be unarchived. Possible values are: archive, unarchive. Default is archive. | Optional |

#### Command example

```!prisma-cloud-compute-archive-audit-incident incident_id="1111"```

#### Human Readable Output

>Incident 1111 was successfully archived

### prisma-cloud-compute-runtime-host-audit-events-list

***
Retrieves the runtime host audit events.

#### Base Command

`prisma-cloud-compute-runtime-host-audit-events-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| clusters | A comma-separated list of cluster names. | Optional |
| namespaces | A comma-separated list of namespace names. | Optional |
| audit_id | A comma-separated list of audit event IDs. | Optional |
| profile_id | A comma-separated list of runtime profile IDs. | Optional |
| image_name | A comma-separated list of image names. | Optional |
| container | A comma-separated list of container names. | Optional |
| container_id | A comma-separated list of container IDs. | Optional |
| type | A comma-separated list of audit event types. | Optional |
| effect | A comma-separated list of audit event effects. | Optional |
| user | A comma-separated list of users. | Optional |
| os | A comma-separated list of operating systems. | Optional |
| app | A comma-separated list of applications. | Optional |
| hostname | A comma-separated list of hostnames. | Optional |
| time | Time is used to filter by audit time. | Optional |
| attack_type | AttackTypes is used to filter by runtime audit attack type. | Optional |
| limit | The maximum number of container scan reports to return. Must be between 1-50. Default is 50. | Optional |
| offset | The offset by which to begin listing container scan reports. Default is 0. | Optional |
| all_results | Whether to retrieve all results. The "limit" argument will be ignored. Using this argument may return a lot of results and might slow down the command run time. Therefore, it is not recommended to be used often. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.RuntimeHostAuditEvents._id | String | The audit event ID. |
| PrismaCloudCompute.RuntimeHostAuditEvents.accountID | String | The account ID of the container. |
| PrismaCloudCompute.RuntimeHostAuditEvents.app | String | The app. |
| PrismaCloudCompute.RuntimeHostAuditEvents.attackType | String | The attack type. |
| PrismaCloudCompute.RuntimeHostAuditEvents.attackTechniques | Unknown | Attack technique of the event |
| PrismaCloudCompute.RuntimeHostAuditEvents.collections | Unknown | The collections. |
| PrismaCloudCompute.RuntimeHostAuditEvents.command | String | The command of the audit event. |
| PrismaCloudCompute.RuntimeHostAuditEvents.count | Number | The count of audit events. |
| PrismaCloudCompute.RuntimeHostAuditEvents.effect | String | The audit event effect. |
| PrismaCloudCompute.RuntimeHostAuditEvents.filepath | String | The file path of the audit event. |
| PrismaCloudCompute.RuntimeHostAuditEvents.fqdn | String | The fully qualified domain name used in the audit event. |
| PrismaCloudCompute.RuntimeHostAuditEvents.events.hostname | String | The hostname on which the command was invoked. |
| PrismaCloudCompute.RuntimeHostAuditEvents.md5 | String | The MD5 hash of the file. |
| PrismaCloudCompute.RuntimeHostAuditEvents.msg | String | The audit event message. |
| PrismaCloudCompute.RuntimeHostAuditEvents.pid | Number | The process ID. |
| PrismaCloudCompute.RuntimeHostAuditEvents.processPath | String | The process path. |
| PrismaCloudCompute.RuntimeHostAuditEvents.profileId | String | The profile ID. |
| PrismaCloudCompute.RuntimeHostAuditEvents.provider | String | The provider of the container. |
| PrismaCloudCompute.RuntimeHostAuditEvents.region | String | The region of the container. |
| PrismaCloudCompute.RuntimeHostAuditEvents.resourceID | String | The resource ID of the event. |
| PrismaCloudCompute.RuntimeHostAuditEvents.ruleName | String | The rule name. |
| PrismaCloudCompute.RuntimeHostAuditEvents.severity | String | The severity of the audit event. |
| PrismaCloudCompute.RuntimeHostAuditEvents.time | Date | The audit event time. |
| PrismaCloudCompute.RuntimeHostAuditEvents.type | String | The audit event type. |
| PrismaCloudCompute.RuntimeHostAuditEvents.user | String | The audited event user. |

#### Command example

```!prisma-cloud-compute-runtime-host-audit-events-list limit=1```

#### Context Example

```json
{
    "PrismaCloudCompute": {
        "RuntimeHostAuditEvents": {
            "_id": "2222",
            "accountID": "3333",
            "app": "test.amazon-test-agent.amazon-test-agent",
            "attackType": "unknownOriginBinary",
            "collections": [
                "BDausses_Collection",
                "3333",
### prisma-cloud-compute-logs-defender

***
Download the Defender logs.

#### Base Command

`prisma-cloud-compute-logs-defender`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The Defender hostname. Can be retrieved from the "prisma-cloud-compute-defenders-list" command. | Optional | 
| lines | The number of log lines to fetch. Default is 10. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.Defenders.Hostname | String | The hostname the log was retrieved from. | 
| PrismaCloudCompute.Defenders.Logs.Level | String | The log level. | 
| PrismaCloudCompute.Defenders.Logs.Log | String | The log message. | 
| PrismaCloudCompute.Defenders.Logs.Time | Date | The time of the log. | 


#### Context Example

```json
{
    "PrismaCloudCompute": {
        "Policies": {
            "RuntimeContainerPolicy": {
                "advancedProtectionEffect": "alert",
                "cloudMetadataEnforcementEffect": "alert",
                "collections": [
                    {
                        "accountIDs": [
                            "*"
                        ],
                        "appIDs": [
                            "*"
                        ],
                        "clusters": [
                            "*"
                        ],
                        "codeRepos": [
                            "*"
                        ],
                        "color": "#53EB1C",
                        "containers": [
                            "*"
                        ],
                        "functions": [
                            "*"
                        ],
                        "hosts": [
                            "test-worker01",
                            "test-master02",
                            "test-worker02",
                            "test-worker03"
                        ],
### prisma-cloud-compute-logs-defender-download

***
Download a zip of all Defender logs.

#### Base Command

`prisma-cloud-compute-logs-defender-download`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | The Defender hostname. Can be retrieved from the "prisma-cloud-compute-defenders-list" command. | Optional | 
| lines | The number of log lines to fetch. Default is 100. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| InfoFile.Name | String | The file name. | 
| InfoFile.EntryID | String | The File entry ID. | 
| InfoFile.Size | Number | The file size. | 
| InfoFile.Type | String | The file type. | 
| InfoFile.Info | String | Basic information of the file. | 
| InfoFile.Extension | String | File extension. | 

                    "defaultEffect": "alert",
                    "deniedIPs": [],
                    "deniedIPsEffect": "disable",
                    "disabled": false,
                    "listeningPorts": {
                        "allowed": [],
                        "denied": [],
                        "effect": "disable"
                    },
                    "modifiedProcEffect": "alert",
                    "outboundPorts": {
                        "allowed": [
                            {
                                "deny": false,
                                "end": 6443,
                                "start": 6443
                            }
                        ],
                        "denied": [],
                        "effect": "disable"
                    },
                    "portScanEffect": "alert",
                    "rawSocketsEffect": "alert"
                },
                "owner": "test2@paloaltonetworks.com",
                "previousName": "",
                "processes": {
                    "allowedList": [],
                    "checkParentChild": true,
                    "cryptoMinersEffect": "alert",
                    "defaultEffect": "alert",
                    "deniedList": {
                        "effect": "disable",
                        "paths": []
                    },
                    "disabled": false,
                    "lateralMovementEffect": "alert",
                    "modifiedProcessEffect": "alert",
                    "reverseShellEffect": "alert",
                    "suidBinariesEffect": "disable"
                },
                "skipExecSessions": true,
                "wildFireAnalysis": "alert"
            }
        }
    }
}
```

#### Human Readable Output

>### Runtime Container Policy Events Information
>
>|Name|Owner|Modified|
>|---|---|---|
>| rke-monitor-rule | avega@paloaltonetworks.com | 2024-01-12T16:52:25.358Z |

## General Note

* Do not use the reset last run button as it will cause incidents duplications to the instance.
* In case you pressed reset last run button and you get duplicated incidents, run **prisma-cloud-compute-unstuck-fetch-stream** command.
### prisma-cloud-compute-unstuck-fetch-stream

***
Use this command to unstuck the fetch stream in case it's getting duplicated incidents.

#### Base Command

`prisma-cloud-compute-unstuck-fetch-stream`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
### prisma-cloud-compute-ci-scan-results-list

***
Retrieves all scan reports for images scanned by the Jenkins plugin or twistcli. Maps to Monitor > Vulnerabilities > Images > CI in the Console UI. The default will retrieve only the passed scans.

#### Base Command

`prisma-cloud-compute-ci-scan-results-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_ids | A comma-separated list of cloud account IDs to filter the result by. | Optional | 
| resource_ids | A comma-separated list of resource IDs to scope the query by. | Optional | 
| region | A comma-separated list of regions to scope the query by. | Optional | 
| scan_id | Scan ID used in the image layers fetch. | Optional | 
| image_id | Image ID of scanned image. | Optional | 
| job_name | A comma-separated list of Jenkins job names. | Optional | 
| search | Retrieves the result for a search term. | Optional | 
| pass | Indicates whether to filter on passed scans (true) or not (false). Possible values are: true, false. Default is true. | Optional | 
| scan_time_to | Filters results by end datetime. Based on scan time. | Optional | 
| scan_time_from | Filters results by start datetime. Based on scan time. | Optional | 
| limit | The maximum number of CI scan results to return. Must be between 1-50. Default is 50. | Optional | 
| offset | The offset by which to begin listing CI scan results. Default is 0. | Optional | 
| all_results | Whether to retrieve all results. The "limit" argument will be ignored. Might slow down the command run time. Using this argument may return a lot of results and is not recommended to be used often. Possible values are: true, false. Default is false. | Optional | 
| verbose | Whether to retrieve all fields of each scan result. When used with the "all_results" argument, it may return a lot of results in a file. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.CIScan._id | String | The scan ID. | 
| PrismaCloudCompute.CIScan.time | String | The scan time. | 
| PrismaCloudCompute.CIScan.pass | Boolean | Whether the scan passed. | 
| PrismaCloudCompute.CIScan.vulnFailureSummary | String | Vulnerability scan failure summary. | 
| PrismaCloudCompute.CIScan.version | String | The scan version. | 
| PrismaCloudCompute.CIScan.entityInfo._id | String | The scanned entity ID. | 
| PrismaCloudCompute.CIScan.entityInfo.type | String | The scanned entity type. | 
| PrismaCloudCompute.CIScan.entityInfo.hostname | String | The scanned entity hostname. | 
| PrismaCloudCompute.CIScan.entityInfo.scanTime | String | The entity scan time. | 
| PrismaCloudCompute.CIScan.entityInfo.binaries | Unknown | Binaries in the scanned entity. | 
| PrismaCloudCompute.CIScan.entityInfo.Secrets | Unknown | Secrets found in the scanned entity. | 
| PrismaCloudCompute.CIScan.entityInfo.startupBinaries | Unknown | Startup binaries in the scanned entity. | 
| PrismaCloudCompute.CIScan.entityInfo.osDistro | String | The OS distribution. | 
| PrismaCloudCompute.CIScan.entityInfo.osDistroVersion | String | The OS distribution version. | 
| PrismaCloudCompute.CIScan.entityInfo.osDistroRelease | String | The OS distribution release. | 
| PrismaCloudCompute.CIScan.entityInfo.distro | String | The distribution. | 
| PrismaCloudCompute.CIScan.entityInfo.packages | Unknown | Packages in the scanned entity. | 
| PrismaCloudCompute.CIScan.entityInfo.files | Unknown | Files in the scanned entity. | 
| PrismaCloudCompute.CIScan.entityInfo.packageManager | Boolean | The package manager. | 
| PrismaCloudCompute.CIScan.entityInfo.applications | Unknown | Applications in the scanned entity. | 
| PrismaCloudCompute.CIScan.entityInfo.isARM64 | Boolean | Whether the scanned entity is ARM64. | 
| PrismaCloudCompute.CIScan.entityInfo.packageCorrelationDone | Boolean | Whether package correlation was done. | 
| PrismaCloudCompute.CIScan.entityInfo.redHatNonRPMImage | Boolean | Whether it is a RedHat non-RPM image. | 
| PrismaCloudCompute.CIScan.entityInfo.foundSecrets | Unknown | Whether secrets were found. | 
| PrismaCloudCompute.CIScan.entityInfo.secretScanMetrics | Unknown | Secret scan metrics. | 
| PrismaCloudCompute.CIScan.entityInfo.image | Unknown | The scanned image. | 
| PrismaCloudCompute.CIScan.entityInfo.history | Unknown | The image history. | 
| PrismaCloudCompute.CIScan.entityInfo.id | String | The entity ID. | 
| PrismaCloudCompute.CIScan.entityInfo.complianceIssues | Unknown | Compliance issues found. | 
| PrismaCloudCompute.CIScan.entityInfo.allCompliance | Unknown | All compliance data. | 
| PrismaCloudCompute.CIScan.entityInfo.vulnerabilities | Unknown | Vulnerabilities found. | 
| PrismaCloudCompute.CIScan.entityInfo.repoTag | Unknown | Repository tag. | 
| PrismaCloudCompute.CIScan.entityInfo.tags | Unknown | Image tags. | 
| PrismaCloudCompute.CIScan.entityInfo.repoDigests | Unknown | Repository digests. | 
| PrismaCloudCompute.CIScan.entityInfo.creationTime | String | Image creation time. | 
| PrismaCloudCompute.CIScan.entityInfo.pushTime | String | Image push time. | 
| PrismaCloudCompute.CIScan.entityInfo.vulnerabilitiesCount | Number | Number of vulnerabilities found. | 
| PrismaCloudCompute.CIScan.entityInfo.complianceIssuesCount | Number | Number of compliance issues found. | 
| PrismaCloudCompute.CIScan.entityInfo.vulnerabilityDistribution | Unknown | Vulnerability distribution data. | 
| PrismaCloudCompute.CIScan.entityInfo.complianceDistribution | Unknown | Compliance distribution data. | 
| PrismaCloudCompute.CIScan.entityInfo.vulnerabilityRiskScore | Number | Vulnerability risk score. | 
| PrismaCloudCompute.CIScan.entityInfo.complianceRiskScore | Number | Compliance risk score. | 
| PrismaCloudCompute.CIScan.entityInfo.layers | Unknown | Image layers data. | 
| PrismaCloudCompute.CIScan.entityInfo.topLayer | String | Top image layer data. | 
| PrismaCloudCompute.CIScan.entityInfo.riskFactors | Unknown | Risk factors data. | 
| PrismaCloudCompute.CIScan.entityInfo.labels | Unknown | Image labels. | 
| PrismaCloudCompute.CIScan.entityInfo.installedProducts | Unknown | Installed products data. | 
| PrismaCloudCompute.CIScan.entityInfo.scanVersion | String | The scan version. | 
| PrismaCloudCompute.CIScan.entityInfo.scanBuildDate | String | The scan build date. | 
| PrismaCloudCompute.CIScan.entityInfo.firstScanTime | String | First scan time. | 
| PrismaCloudCompute.CIScan.entityInfo.cloudMetadata | Unknown | Cloud metadata. | 
| PrismaCloudCompute.CIScan.entityInfo.instances | Unknown | Instance data. | 
| PrismaCloudCompute.CIScan.entityInfo.hosts | Unknown | Host data. | 
| PrismaCloudCompute.CIScan.entityInfo.err | String | Error data. | 
| PrismaCloudCompute.CIScan.entityInfo.collections | Unknown | Collection data. | 
| PrismaCloudCompute.CIScan.entityInfo.scanID | Number | The scan ID. | 
| PrismaCloudCompute.CIScan.entityInfo.trustStatus | String | Trust status data. | 
| PrismaCloudCompute.CIScan.entityInfo.firewallProtection | Unknown | Firewall protection data. | 
| PrismaCloudCompute.CIScan.entityInfo.appEmbedded | Boolean | Whether app is embedded. | 
| PrismaCloudCompute.CIScan.entityInfo.wildFireUsage | Unknown | WildFire usage data. | 
| PrismaCloudCompute.CIScan.entityInfo.agentless | Boolean | Whether it is an agentless scan. | 
| PrismaCloudCompute.CIScan.entityInfo.malwareAnalyzedTime | String | Malware analyzed time. | 
### prisma-cloud-compute-trusted-images-list

***
Returns the trusted registries, repositories, and images. Maps to the image table in Defend > Compliance > Trusted Images in the Console UI.

#### Base Command

`prisma-cloud-compute-trusted-images-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.TrustedImage.policy.enabled | Boolean | Whether the trusted image policy is enabled. | 
| PrismaCloudCompute.TrustedImage.policy._id | String | The ID of the trusted image policy. | 
| PrismaCloudCompute.TrustedImage.policy.rules.name | String | The name of the trusted image rule. | 
| PrismaCloudCompute.TrustedImage.policy.rules.allowedGroups | Unknown | The allowed groups for the trusted image rule. | 
| PrismaCloudCompute.TrustedImage.policy.rules.effect | String | The effect of the trusted image rule. | 
| PrismaCloudCompute.TrustedImage.policy.rules.modified | Date | The last modified timestamp for the trusted image rule. | 
| PrismaCloudCompute.TrustedImage.policy.rules.previousName | String | The previous name of the trusted image rule. | 
| PrismaCloudCompute.TrustedImage.policy.rules.owner | String | The owner of the trusted image rule. | 
| PrismaCloudCompute.TrustedImage.policy.rules.disabled | Boolean | Whether the trusted image rule is disabled. | 
| PrismaCloudCompute.TrustedImage.policy.rules.collections | Unknown | The collections for the trusted image rule. | 
| PrismaCloudCompute.TrustedImage.groups.modified | Date | The last modified timestamp for the trusted image group. | 
| PrismaCloudCompute.TrustedImage.groups.owner | String | The owner of the trusted image group. | 
| PrismaCloudCompute.TrustedImage.groups.name | String | The name of the trusted image group. | 
| PrismaCloudCompute.TrustedImage.groups.previousName | String | The previous name of the trusted image group. | 
| PrismaCloudCompute.TrustedImage.groups._id | String | The ID of the trusted image group. | 
| PrismaCloudCompute.TrustedImage.groups.images | Unknown | The images in the trusted image group. | 
### prisma-cloud-compute-container-scan-results-list

***
Retrieves container scan reports. Maps to Monitor > Compliance > Containers in the Console UI.

#### Base Command

`prisma-cloud-compute-container-scan-results-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collections | A comma-separated list of collection names that you have defined in Prisma Cloud Compute. | Optional | 
| account_ids | A comma-separated list of cloud account IDs. | Optional | 
| clusters | A comma-separated list of clusters to filter by. | Optional | 
| namespaces | A comma-separated list of namespaces to filter by. | Optional | 
| resource_ids | A comma-separated list of resource IDs to scope the query by. | Optional | 
| region | A comma-separated list of regions to scope the query by. | Optional | 
| container_ids | A comma-separated list of container IDs to retrieve details for. | Optional | 
| profile_id | A comma-separated list of runtime profile IDs to filter by. | Optional | 
| image_name | A comma-separated list of image names to filter by. | Optional | 
| image_id | A comma-separated list of image IDs to filter by. | Optional | 
| hostname | A comma-separated list of hostnames to filter by. | Optional | 
| compliance_ids | A comma-separated list of compliance IDs to filter by. | Optional | 
| agentless | Whether to filter by agentless scans. Possible values are: true, false. | Optional | 
| search | Term to search for. | Optional | 
| limit | The maximum number of container scan reports to return. Must be between 1-50. Default is 50. | Optional | 
| offset | The offset by which to begin listing container scan reports. Default is 0. | Optional | 
| all_results | Whether to retrieve all results. The "limit" argument will be ignored. Using this argument may return a lot of results and might slow down the command run time. Therefore, it is not recommended to be used often. Possible values are: true, false. Default is false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.ContainersScanResults._id | String | The container scan ID. | 
| PrismaCloudCompute.ContainersScanResults.hostname | String | The container hostname. | 
| PrismaCloudCompute.ContainersScanResults.scanTime | Date | The container scan time. | 
| PrismaCloudCompute.ContainersScanResults.collections | Unknown | The collections the container belongs to. | 
| PrismaCloudCompute.ContainersScanResults.firewallProtection | Unknown | Firewall protection data. | 
| PrismaCloudCompute.ContainersScanResults.csa | Boolean | Container security assessment data. | 
| PrismaCloudCompute.ContainersScanResults.info.name | String | The container name. | 
| PrismaCloudCompute.ContainersScanResults.info.profileID | String | The profile ID. | 
| PrismaCloudCompute.ContainersScanResults.info.infra | Boolean | Whether the container is infrastructure. | 
| PrismaCloudCompute.ContainersScanResults.info.id | String | The container ID. | 
| PrismaCloudCompute.ContainersScanResults.info.ImageID | String | The container image ID. | 
| PrismaCloudCompute.ContainersScanResults.info.image | String | The container image. | 
| PrismaCloudCompute.ContainersScanResults.info.imageName | String | The container image name. | 
| PrismaCloudCompute.ContainersScanResults.info.app | String | The container application name. | 
| PrismaCloudCompute.ContainersScanResults.info.namespace | String | The container namespace. | 
| PrismaCloudCompute.ContainersScanResults.info.cluster | String | The container cluster name. | 
| PrismaCloudCompute.ContainersScanResults.info.clusterType | String | The container cluster type. | 
| PrismaCloudCompute.ContainersScanResults.info.externalLabels | Unknown | Container external labels. | 
| PrismaCloudCompute.ContainersScanResults.info.complianceIssues | Unknown | Compliance issues found. | 
| PrismaCloudCompute.ContainersScanResults.info.allCompliance | Unknown | All compliance data. | 
| PrismaCloudCompute.ContainersScanResults.info.complianceIssuesCount | Number | Number of compliance issues. | 
| PrismaCloudCompute.ContainersScanResults.info.complianceRiskScore | Number | Compliance risk score. | 
| PrismaCloudCompute.ContainersScanResults.info.complianceDistribution | Unknown | Compliance issue distribution. | 
| PrismaCloudCompute.ContainersScanResults.info.processes | Unknown | Container processes data. | 
| PrismaCloudCompute.ContainersScanResults.info.network | Unknown | Network data. | 
| PrismaCloudCompute.ContainersScanResults.info.labels | Unknown | Container labels. | 
| PrismaCloudCompute.ContainersScanResults.info.installedProducts | Unknown | Installed products data. | 
| PrismaCloudCompute.ContainersScanResults.info.cloudMetadata | Unknown | Cloud metadata. | 
| PrismaCloudCompute.ContainersScanResults.info.startTime | Date | Container start time. | 
### prisma-cloud-compute-hosts-list

***
Returns minimal information that includes hostname, distro, distro-release, collections, clusters, and agentless about all deployed hosts.

#### Base Command

`prisma-cloud-compute-hosts-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| collections | A comma-separated list of collection names that you have defined in Prisma Cloud Compute. | Optional | 
| account_ids | A comma-separated list of cloud account IDs. | Optional | 
| clusters | A comma-separated list of clusters to filter by. | Optional | 
| resource_ids | A comma-separated list of resource IDs to scope the query by. | Optional | 
| region | A comma-separated list of regions to scope the query by. | Optional | 
| hostname | A comma-separated list of hostnames to filter by. | Optional | 
| compliance_ids | A comma-separated list of compliance IDs to filter by. | Optional | 
| agentless | Whether to filter by agentless scans. Possible values are: true, false. | Optional | 
| search | Term to search for. | Optional | 
| limit | The maximum number of container scan reports to return. Must be between 1-50. Default is 50. | Optional | 
| offset | The offset by which to begin listing container scan reports. Default is 0. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| PrismaCloudCompute.Hosts._id | String | The host ID. | 
| PrismaCloudCompute.Hosts.type | String | The host type. | 
| PrismaCloudCompute.Hosts.hostname | String | The host hostname. | 
| PrismaCloudCompute.Hosts.scanTime | Date | The host scan time. | 
| PrismaCloudCompute.Hosts.Secrets | Unknown | Secrets found on the host. | 
| PrismaCloudCompute.Hosts.osDistro | String | The OS distribution. | 
| PrismaCloudCompute.Hosts.osDistroVersion | String | The OS distribution version. | 
| PrismaCloudCompute.Hosts.osDistroRelease | String | The OS distribution release. | 
| PrismaCloudCompute.Hosts.distro | String | The host distribution. | 
| PrismaCloudCompute.Hosts.foundSecrets | Boolean | Whether secrets were found. | 
| PrismaCloudCompute.Hosts.vulnerabilitiesCount | Number | Number of vulnerabilities found. | 
| PrismaCloudCompute.Hosts.complianceIssuesCount | Number | Number of compliance issues found. | 
| PrismaCloudCompute.Hosts.vulnerabilityRiskScore | Number | The host's vulnerability risk score. | 
| PrismaCloudCompute.Hosts.complianceRiskScore | Number | The host's compliance risk score. | 
| PrismaCloudCompute.Hosts.riskFactors | Unknown | Risk factors for the host. | 
| PrismaCloudCompute.Hosts.collections | Unknown | The collections the host belongs to. | 
| PrismaCloudCompute.Hosts.agentless | Boolean | Whether the host was scanned agentlessly. | 
### prisma-cloud-compute-archive-audit-incident

***
Acknowledges an incident and moves it to an archived state.

#### Base Command

`prisma-cloud-compute-archive-audit-incident`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident ID. | Required | 
| action | Action for the command. archive - incident will be archived, unarchive - incident will be unarchived. Possible values are: archive, unarchive. Default is archive. | Optional | 

#### Context Output

There is no context output for this command.
### prisma-cloud-compute-custom-feeds-malware-remove

***
Remove custom MD5 malware hashes.

#### Base Command

`prisma-cloud-compute-custom-feeds-malware-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | The name that will be attached to the MD5 records. | Required | 
| md5 | A comma-separated list of MD5 hashes to be added. | Required | 

#### Context Output

There is no context output for this command.
