<~XSIAM>

## Overview

Commvault is an enterprise-grade backup and recovery solution that protects data across on-premises, cloud, and hybrid environments.
It offers centralized management, automation, and policy-driven workflows to simplify data protection and ensure compliance.
With built-in ransomware protection, disaster recovery, and cloud optimization, Commvault helps organizations safeguard and rapidly restore critical business data.

## This pack includes

Data normalization capabilities:

* Parsing and Modeling Rules normalize logs ingested via the Cortex XSIAM HTTP Collector.
* The *`commvault_backupsolution_raw`* dataset enables querying Commvault Backup logs in XQL Search.

## Supported log types

* Audit
* Events
* Alerts

### Supported timestamp formats

Timestamp ingestion is supported for all of the categories using UTC EPOCH time from the **UTC_Timestamp** field.
In addition, there are two more ingestion options for Alerts and Events:

| Category                    | Ingested Log Field                 | Supported Format                    |
|:----------------------------|:--------------------------------------|:--------------------------------------|
| Events  | event_date                            | [%h %e %X %Y] (E.g. Feb 18 04:00:05 2025)                            |
| Alerts  | alerttime                            | [%e %h %Y %X] (E.g. 5 Nov 2024 11:38:41)                            |

***

## Data Collection

### Commvault Backup side

1. From the navigation pane, go to **Manage** &rarr; **System**.
2. Click the **SIEM connector** tile.
3. Click **Add connector**.
4. On the **General** tab, enter the following information:
   * Connector **name**: Enter a name for the connector.
   * Connector **type**: From the list, select Webhook.
   * **Streaming data**: From the list, select the data that you want to send to the webhook.
5. Click **Next**.
6. On the **Connector Definition** tab, enter the following information:
   * **Webhook**: Type the name of the webhook, then select a webhook from the list.
   * **Alerts, Audit, and Events Template**: You must provide the template that is suitable for the particular third-party webhook application that you configured.
7. Click **Submit**.

For more information, see the product [documentation](https://documentation.commvault.com/v11/software/adding_siem_connector_for_webhook.html).

### Cortex XSIAM side - Custom - HTTP based Collector

1. Navigate to **Settings** -> **Data Sources** -> **Add Data Source**.
2. If you have already configured a **Custom - HTTP based Collector**, select the **3 dots**, and then select **+ Add New Instance**. If not, select **+ Add Data Source**, search for "http" and then select **Connect**.
3. Set the following values:

    | Parameter    | Value                                                                                                                                           |
    |:-------------|:-------------------------------------------|
    | `Name`        |  `<Vendor>` `<Product>` Logs           |
    | `Compression` | uncompressed     |
    | `Log Format`  | JSON     |
    | `Vendor`      | commvault                     |
    | `Product`     | backupsolution                    |

4. Creating a new HTTP Log Collector will allow you to generate a unique token, please save it since it will be used later.
5. Click the 3 dots sign next to the newly created instance and copy the API Url, it will also be used later.

For more information, see [Set up an HTTP log collector to receive logs](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-3.x-Documentation/Set-up-an-HTTP-log-collector-to-receive-logs).

</~XSIAM>
