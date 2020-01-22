![image](https://user-images.githubusercontent.com/49071222/72906531-0e452a00-3d3b-11ea-8703-8b97ddf30be0.png)


## Overview

This integration provides the ability to import **Palo Alto Networks - Prisma Cloud Compute** alerts into Demisto

## Use Cases
Manage Prisma Cloud Compute alerts in Demisto, analyze, assign tasks, open tickets on other platforms, create playbooks, and much more

Before you can use the Prisma Cloud Compute integration on Demisto, there are several configuration steps required on the Prisma Cloud Platform
## Prerequisites
### Configure Demisto alert profile in Prisma Cloud Compute:

1. Login to your Prisma Cloud Compute console
1. Navigate to **Manage > Alerts**
1. Create a new alert profile by clicking the **Add Profile** button
1. Choose **Demisto** from the provider list on the left and choose what would you like Demisto to be alerted about from the alert triggers on the right
1. Click **Save** to save the alert profile

## Configure Prisma Cloud Compute on Demisto

1. Navigate to **Settings > Integrations > Servers & Services**
1. Search for **Prisma Cloud Compute**
1. Click **Add instance** to create and configure a new integration instance
* **Name**: A textual name for the integration instance
* **Fetches incidents**: Check if you wish this integration instance would fetch alerts from Prisma Cloud Compute.
* **Prisma Cloud Compute Console URL**: The URL address of your Prisma Cloud Compute console, copy the address from the alert profile created in the previous step on Prisma Cloud Compute
* **Prisma Cloud Compute Project Name (if applies)**: If using projects in Prisma Cloud Compute, the project name should be configured here. Copy the project name from the alert profile created in the previous step on Prisma Cloud Compute
* **Trust any certificate (not secure)**: Check to skip verification of the CA certificate (not recommended)
* **Use system proxy settings**: Check to use the system proxy settings
* **Credentials**: Prisma Cloud Compute login credentials
* **Prisma Cloud Compute CA Certificate**: CA Certificate used by Prismae Cloud Compute, copy the certificate from the alert profile created in the previous step on Prisma Cloud Compute
4. Click **Test** to validate the new instance
5. Click **Done** to save the configured instance


## Using the integration and scripts
The integration is provided with 4 default playbooks and 4 scripts which are being used by them

#### Scripts:

* PrismaCloudComputeParseAuditAlert
* PrismaCloudComputeParseComplianceAlert
* PrismaCloudComputeParseVulnerabilityAlert
* PrismaCloudComputeParseCloudDiscoveryAlert

The purpose of those scripts is to parse the raw JSON alerts into a Demisto objects that can be used in playbooks.
To understand this better let's look at the _Prisma Cloud Compute - Vulnerability Alert_ playbook:


![image](https://user-images.githubusercontent.com/49071222/72902982-1601d000-3d35-11ea-8be2-a12ac8ea8862.png)


* When that playbook is triggered, a task called **Parse Vulnerability Alert** runs
* It runs the script **PrismaCloudComputeParseVulnerabilityAlert** where it takes as input the `prismacloudcomputerawalertjson` field of the incident (the raw JSON alert data) 
* Check the **outputs** to see the outputs of this task:


![image](https://user-images.githubusercontent.com/49071222/72903545-1189e700-3d36-11ea-9a35-81b756a5fc6d.png)


**Now we can add any automation tasks to the playbook that would check and respond according to the received outputs we see above**



## Troubleshooting
If any alerts are missing on Demisto, check the integration status on the integration page:
![image](https://user-images.githubusercontent.com/49071222/72086124-18b0fe00-330f-11ea-894b-6b2f9f0528fd.png)

If you're having further issues, contact us at [support@demisto.com](mailto:support@demisto.com) and attach the server logs
