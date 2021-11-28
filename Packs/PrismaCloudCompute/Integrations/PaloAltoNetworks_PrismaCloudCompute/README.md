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
```prisma-cloud-compute-profile-host-list hostName=*249* namespace=prod```

#### Human Readable Output

### Apps
|HostId|AppName|StartupProcess|User|LaunchTime|
|---|---|---|---|---|
| host249 | ssh | /usr/sbin/sshd | root | 2020-11-10T09:37:42.301Z |
| host249 | docker | /usr/bin/dockerd | root | 2020-11-10T09:37:42.301Z |
| host249 | atd | /usr/sbin/atd | root | 2020-11-10T09:37:42.302Z |
| host249 | acpid | /usr/sbin/acpid | root | 2020-11-10T09:37:42.302Z |
| host249 | cron | /usr/sbin/cron | root | 2020-11-10T09:37:42.302Z |
| host249 | apt-daily | /bin/dash | root | 2020-11-10T11:41:34.631Z |
| host249 | snapd | /usr/lib/snapd/snapd | root | 2021-02-11T06:23:47.57Z |
| host249 | systemd | /lib/systemd/systemd | root | 2021-09-02T10:25:30.845Z |
### SSH Events
|HostId|User|Ip|ProcessPath|Command|Time|
|---|---|---|---|---|---|
| host249 | ubuntu | 1.1.1.1 | /usr/bin/clear_console | /usr/bin/clear_console -q | 2021-09-02T11:49:33.033Z |
| host249 | ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -alF | 2021-09-02T11:04:01.486Z |
| host249 | ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -alF | 2021-09-02T11:03:57.779Z |
| host249 | ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -alF | 2021-09-02T11:03:53.468Z |
| host249 | ubuntu | 1.1.1.1 | /usr/bin/dircolors | /usr/bin/dircolors | 2021-09-02T11:03:52.617Z |
| host249 | ubuntu | 1.1.1.1 | /usr/bin/dirname | dirname /usr/bin/lesspipe | 2021-09-02T11:03:52.614Z |
| host249 | ubuntu | 1.1.1.1 | /usr/bin/basename | basename /usr/bin/lesspipe | 2021-09-02T11:03:52.613Z |
| host249 | ubuntu | 1.1.1.1 | /bin/dash | /bin/sh /usr/bin/lesspipe | 2021-09-02T11:03:52.612Z |
| host249 | ubuntu | 1.1.1.1 | /usr/bin/groups | /usr/bin/groups | 2021-09-02T11:03:52.609Z |
| host249 | ubuntu | 1.1.1.1 | /bin/bash | /bin/bash | 2021-09-02T11:03:52.605Z |
| host249 | ubuntu | 1.1.1.1 | /bin/su | /bin/su | 2021-09-02T11:03:52.597Z |
| host249 | ubuntu | 1.1.1.1 | /usr/bin/sudo | /usr/bin/sudo | 2021-09-02T11:03:52.573Z |
| host249 | ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -lt | 2021-09-02T11:03:45.66Z |
| host249 | ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -ltr | 2021-09-02T10:27:24.429Z |
| host249 | ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -alF | 2021-09-02T10:27:22.841Z |
| host249 | ubuntu | 1.1.1.1 | /bin/ls | ls --color=auto -alF | 2021-09-02T10:27:20.337Z |
| host249 | ubuntu | 1.1.1.1 | /bin/ls | ls /etc/bash_completion.d | 2021-09-02T10:27:18.865Z |
| host249 | ubuntu | 1.1.1.1 | /usr/bin/dircolors | /usr/bin/dircolors | 2021-09-02T10:27:18.848Z |
| host249 | ubuntu | 1.1.1.1 | /usr/bin/dirname | dirname /usr/bin/lesspipe | 2021-09-02T10:27:18.844Z |
| host249 | ubuntu | 1.1.1.1 | /usr/bin/basename | basename /usr/bin/lesspipe | 2021-09-02T10:27:18.843Z |
| host249 | ubuntu | 1.1.1.1 | /bin/dash | /bin/sh /usr/bin/lesspipe | 2021-09-02T10:27:18.842Z |
| host249 | ubuntu | 1.1.1.1 | /bin/ls | ls /etc/bash_completion.d | 2021-09-02T10:27:18.818Z |
| host249 | ubuntu | 1.1.1.1 | /bin/bash | /bin/bash | 2021-09-02T10:27:18.8Z |
| host249 | ubuntu | 2.2.2.2 | /usr/bin/scp | /usr/bin/scp | 2021-09-02T10:27:06.479Z |
| host249 | ubuntu | 2.2.2.2 | /bin/bash | bash -c scp -t . | 2021-09-02T10:27:06.475Z |
| host249 | root | 2.2.2.2 | /bin/sleep | /bin/sleep | 2021-09-02T10:26:52.758Z |
| host249 | root | 2.2.2.2 | /bin/bash | bash -c echo 'Please login as the user "ubuntu" rather than the user "root".';echo;sleep 10 | 2021-09-02T10:26:52.754Z |
| host249 | root | 1.1.1.1 | /bin/sleep | /bin/sleep | 2021-09-02T10:25:31.277Z |
| host249 | root | 1.1.1.1 | /bin/bash | bash -c echo 'Please login as the user "ubuntu" rather than the user "root".';echo;sleep 10 | 2021-09-02T10:25:31.273Z |


