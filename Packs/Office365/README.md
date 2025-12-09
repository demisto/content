# Office 365

<~XSIAM>

## Overview

Office 365 is a subscription-based service that provides a comprehensive suite of productivity apps, combined with intelligent cloud services for collaboration, communication, file storage, security and management.

## This Pack Includes

### Data Normalization and Querying Capabilities

* Data modeling rules to normalize Microsoft Office 365 logs that are ingested via the _Office 365_ integration into Cortex XSIAM.
* Querying ingested logs in XQL Search using the datasets below:

* General &rarr; `msft_o365_general_raw`
* Exchange Online &rarr; `msft_o365_exchange_online_raw`
* SharePoint Online &rarr; `msft_o365_sharepoint_online_raw`
* DLP &rarr; `msft_o365_dlp_raw`
* Azure AD &rarr; `msft_o365_azure_ad_raw`

## Supported Log Category

* Audit

### Supported Timestamp Formats

The ingestion is made using the CreationTime field for UTC (+00:00) in the following formats:

* yyyy-mm-ddThh:mm:ss
* yyyy-mm-ddThh:mm:ss.ms
* yyyy-mm-ddThh:mm:ssZ
* yyyy-mm-ddThh:mm:ss.msZ
* yyyy-mm-dd hh:mm:ss UTC
* yyyy-mm-dd hh:mm:ss.ms UTC

For the msft_o365_emails_raw dataset, ingestion is being made with the createdDateTime field.

## Enable Data Collection

### Native O365 Collector

Configure Cortex XSIAM Office 365 Native Collector on your Cortex XSIAM tenant:

1. On the left panel, click **Settings** &rarr; **Data Sources**
2. At the top-right corner, click **Add Data Source**
3. Search for **Office 365** and click **Connect**.

To create or configure the Office 365 collector, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Documentation/Ingest-Logs-from-Microsoft-Office-365).

To ingest _email logs and data_ from Microsoft Office 365, use the [Microsoft 365 email collector](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-logs-and-data-from-Microsoft-365).
The Microsoft 365 collector ingests data into the following datasets:

* `msft_o365_emails_raw`
* `msft_o365_users_raw`
* `msft_o365_groups_raw`
* `msft_o365_devices_raw`
* `msft_o365_mailboxes_raw`
* `msft_o365_rules_raw`
* `msft_o365_contacts_raw`

For more detailed configuration instructions, follow the guide under section _Configure ingestion into Cortex XSIAM_ [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-logs-and-data-from-Microsoft-365).

**Pay Attention**:
In order to normalize **Azure AD** (`msft_azure_ad_raw`) and **Azure AD Audit** (`msft_azure_ad_audit_raw`) logs, install the Microsoft Entra ID pack.

![Office_365_Collector_Settings](./././doc_files/office365_image1.png)

</~XSIAM>
