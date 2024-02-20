# Prisma Cloud Compute
This pack includes Cortex XSIAM content.

<~XSIAM>
A step-by-step configuration process is available at Cortex XSIAM Administrator Guide- [Ingest Alerts from Prisma Cloud Compute](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Alerts-from-Prisma-Cloud). 

## Configuration on XSIAM
1. Click **Settings** > **Data Sources**.
2. In the Prisma Cloud Compute Collector configuration, click **Add Instance** to begin a new alerts integration.
3. Specify the name for the Prisma Cloud Compute Collector displayed in Cortex XSIAM.
4. Save & Generate Token. The token is displayed in a blue box, which is blurred in the image below.
   * Click the Copy icon next to the Username and Password, and record them in a safe place, as you will need to provide them when you configure the Prisma Cloud Compute Collector for alerts integration. If you forget to record the key and close the window, you will need to generate a new key and repeat this process. When you are finished, click **Done** to close the window.
5. Copy api url.
   * In the Data Sources page for the Prisma Cloud Compute Collector that you created, click **Copy api url**, and record it somewhere safe. You will need to provide this API URL when you set the Incoming Webhook URL as part of the configuration in Prisma Cloud Compute.

**Note**:
The URL format for the tenant is `https://api-<tenant name>.xdr.us.paloaltonetworks.com/logs/v1/prisma`.

## Configuration on Prisma Cloud Compute
1. In Prisma Cloud Compute, create a webhook as explained in the [Webhook Alerts](https://docs.paloaltonetworks.com/prisma/prisma-cloud/prisma-cloud-admin-compute/alerts/webhook) section of the Prisma Cloud Administrator’s Guide (Compute).
   * Config file for Webhook:
```json
//{
  "type": "#type",
  "time": "#time",
  "container": "#container",
  "containerID": "#containerID",
  "image": "#image",
  "imageID": "#imageID",
  "tags": "#tags",
  "host": "#host",
  "fqdn": "#fqdn",
  "function": "#function",
  "region": "#region",
  "provider": "#provider",
  "osRelease": "#osRelease",
  "osDistro": "#osDistro",
  "runtime": "#runtime",
  "appID": "#appID",
  "rule": "#rule",
  "message": "#message",
  "aggregatedAlerts": #aggregatedAlerts,
  "dropped": #dropped,
  "forensics": "#forensics",
  "accountID": "#accountID",
  "category": "#category",
  "command": "#command",
  "startupProcess": "#startupProcess",
  "labels": #labels,
  "collections": #collections,
  "complianceIssues": #complianceIssues,
  "vulnerabilities": #vulnerabilities,
  "clusters": #clusters,
  "namespaces": #namespaces,
  "accountIDs": #accountIDs,
  "user": "#user"
//}
```
2. Use the **Webhook** option to configure the webhook.
3. In **Incoming Webhook URL**, paste the API URL that you copied and recorded from **Copy api url**.
4. In **Credential Options**, select **Basic Authentication**, and use the Username and Password that you saved when you generated the token.
5. Select **Container Runtime**.
6. Click **Save**.
   * In Cortex XSIAM, once alerts start to come in, a green checkmark appears underneath the Prisma Cloud Compute Collector configuration with the amount of data received.
7. After Cortex XSIAM begins receiving data from Prisma Cloud Compute, you can use XQL Search to search for specific data using the `prisma_cloud_compute_raw` dataset.


**Pay Attention**:
Timestamp parsing support is available for the **time** field in `%h %d, %Y %H:%M:%S UTC` format (E.g `Oct 14, 2023 09:16:04 UTC`)


</~XSIAM>

<~XSOAR>
## Overview

This integration lets you import **Palo Alto Networks - Prisma Cloud Compute** alerts into XSOAR

## Use Cases

Manage Prisma Cloud Compute alerts in Cortex XSOAR.
You can create new playbooks, or extend the default ones, to analyze alerts, assign tasks based on your analysis, and open tickets on other platforms.

## Configure Prisma Cloud Compute

Configure Prisma Cloud Compute to send alerts to Cortex XSOAR by creating an alert profile.

1. Login to your Prisma Cloud Compute console.
1. Navigate to **Manage > Alerts**.
1. Create a new alert profile by clicking **Add Profile**.
1. On the left, select **XSOAR** from the provider list.
1. On the right, select the alert triggers. Alert triggers specify which alerts are sent to Cortex XSOAR.
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

The integration ships with four default playbooks:
* Prisma Cloud Compute - Audit Alert v3
* Prisma Cloud Compute - Cloud Discovery Alert
* Prisma Cloud Compute - Compliance Alert
* Prisma Cloud Compute - Vulnerability Alert

3 of the above playbooks (all except _Audit Alert v3_) contain a single script. The script in each playbook encode the raw JSON alerts into Cortex XSOAR objects that can then be used in the playbooks. The scripts are:

* PrismaCloudComputeParseComplianceAlert
* PrismaCloudComputeParseVulnerabilityAlert
* PrismaCloudComputeParseCloudDiscoveryAlert

To better understand how playbooks and scripts interoperate, consider the _Prisma Cloud Compute - Vulnerability Alert_ playbook.

* When the playbook is triggered, a task called **Parse Vulnerability Alert** runs.
* The task runs the **PrismaCloudComputeParseVulnerabilityAlert** script, which takes the `prismacloudcomputerawalertjson` field of the incident (the raw JSON alert data) as input.

![image](https://raw.githubusercontent.com/demisto/content/f808c78aa6c94a09450879c8702a1b7f023f1d4b/Packs/PrismaCloudCompute/doc_files/prisma_alert_raw_input.png)


* Click **outputs** to see how the script transformed the raw JSON input into a XSOAR object.


![image](https://raw.githubusercontent.com/demisto/content/f808c78aa6c94a09450879c8702a1b7f023f1d4b/Packs/PrismaCloudCompute/doc_files/prisma_alert_outputs.png)

At this point, you can add tasks that extend the playbook to check and respond to alerts depending on the properties of the Cortex XSOAR object.

### Audit Alert v3 playbook
This playbook is not similar to the other 3 playbooks. It is a default playbook for parsing and enrichment of Prisma Cloud Compute audit alerts.

The playbook has the following sections:

Enrichment:
- Image details
- Similar container events
- Owner details
- Vulnerabilities
- Compliance details
- Forensics
- Defender logs.

Remediation:
- Block Indicators - Generic v3
- Cloud Response - Generic
- Manual Remediation

Currently, the playbook supports incidents created by **Runtime** and **WAAS** triggers.

## Troubleshooting

If any alerts are missing in Cortex XSOAR, check the status of the integration:

![image](https://raw.githubusercontent.com/demisto/content/f808c78aa6c94a09450879c8702a1b7f023f1d4b/Packs/PrismaCloudCompute/doc_files/prisma_instance.png)
</~XSOAR>