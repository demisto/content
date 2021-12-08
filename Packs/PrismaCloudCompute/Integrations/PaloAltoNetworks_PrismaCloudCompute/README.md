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
| cluster | Clusters is the runtime profile k8s cluster filter. | Optional | 
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
| ip-172-31-23-249.eu-west-1.compute.internal | Ubuntu 16.04 | All,<br>676921422616 |
### Apps
|AppName|StartupProcess|User|LaunchTime|
|---|---|---|---|
| ssh | /usr/sbin/sshd | root | November 10, 2020 09:37:42 AM |
| docker | /usr/bin/dockerd | root | November 10, 2020 09:37:42 AM |
| atd | /usr/sbin/atd | root | November 10, 2020 09:37:42 AM |
| acpid | /usr/sbin/acpid | root | November 10, 2020 09:37:42 AM |
| cron | /usr/sbin/cron | root | November 10, 2020 09:37:42 AM |
| demisto | /usr/local/demisto/server | demisto | November 10, 2020 09:37:42 AM |
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
| ip-172-31-23-249.eu-west-1.compute.internal | Ubuntu 16.04 | All,<br>676921422616 |
| ip-172-31-5-163.eu-west-1.compute.internal | amzn 2 | All,<br>676921422616 |