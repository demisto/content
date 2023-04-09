![image](https://user-images.githubusercontent.com/49071222/72906531-0e452a00-3d3b-11ea-8703-8b97ddf30be0.png)


## Overview

This integration lets you import **Palo Alto Networks - Prisma Cloud Compute** alerts into Demisto

## Use Cases

Manage Prisma Cloud Compute alerts in Demisto.
You can create new playbooks, or extend the default ones, to analyze alerts, assign tasks based on your analysis, and open tickets on other platforms.

## Configure Prisma Cloud Compute

Configure Prisma Cloud Compute to send alerts to Demisto by creating an alert profile.

1. Login to your Prisma Cloud Compute console.
1. Navigate to **Manage > Alerts**.
1. Create a new alert profile by clicking **Add Profile**.
1. On the left, select **Demisto** from the provider list.
1. On the right, select the alert triggers. Alert triggers specify which alerts are sent to Demisto.
1. Click **Save** to save the alert profile

## Configure Cortex XSOAR

1. Navigate to **Settings > Integrations > Servers & Services**.
1. Search for **Prisma Cloud Compute**.
1. Click **Add instance** to create and configure a new integration.
* **Name**: Name for the integration.
* **Fetches incidents**: Configures this integration instance to fetch alerts from Prisma Cloud Compute.
* **Prisma Cloud Compute Console URL**: URL address of your Prisma Cloud Compute console. Copy the address from the alert profile created in Prisma Cloud Compute.
* **Prisma Cloud Compute Project Name (if applies)**: If using projects in Prisma Cloud Compute, enter the project name here. Copy the project name from the alert profile created in Prisma Cloud Compute.
* **Trust any certificate (not secure)**: Skips verification of the CA certificate (not recommended).
* **Use system proxy settings**: Uses the system's proxy settings.
* **Credentials**: Prisma Cloud Compute login credentials.
* **Prisma Cloud Compute CA Certificate**: CA Certificate used by Prisma Cloud Compute. Copy the certificate from the alert profile created in Prisma Cloud Compute.
4. Click **Test** to validate the integration.
5. Click **Done** to save the integration.


## Using the integration and scripts

The integration ships with four default playbooks, along with four scripts that are used by the playbooks. The scripts encode the raw JSON alerts into Demisto objects that can then be used in the playbooks. The scripts are:

* PrismaCloudComputeParseAuditAlert
* PrismaCloudComputeParseComplianceAlert
* PrismaCloudComputeParseVulnerabilityAlert
* PrismaCloudComputeParseCloudDiscoveryAlert


To better understand how playbooks and scripts interoperate, consider the _Prisma Cloud Compute - Vulnerability Alert_ playbook.

* When the playbook is triggered, a task called **Parse Vulnerability Alert** runs.
* The task runs the **PrismaCloudComputeParseVulnerabilityAlert** script, which takes the `prismacloudcomputerawalertjson` field of the incident (the raw JSON alert data) as input.

![image](https://raw.githubusercontent.com/demisto/content/f808c78aa6c94a09450879c8702a1b7f023f1d4b/Packs/PrismaCloudCompute/doc_files/prisma_alert_raw_input.png)


* Click **outputs** to see how the script transformed the raw JSON input into a Demisto object.


![image](https://raw.githubusercontent.com/demisto/content/f808c78aa6c94a09450879c8702a1b7f023f1d4b/Packs/PrismaCloudCompute/doc_files/prisma_alert_outputs.png)

At this point, you can add tasks that extend the playbook to check and respond to alerts depending on the properties of the Demisto object.

## Troubleshooting

If any alerts are missing in Demisto, check the status of the integration:

![image](https://raw.githubusercontent.com/demisto/content/f808c78aa6c94a09450879c8702a1b7f023f1d4b/Packs/PrismaCloudCompute/doc_files/prisma_instance.png)
