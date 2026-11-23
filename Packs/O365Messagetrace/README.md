<~XSIAM>

## Overview
Microsoft Office 365 Message Trace tracks email messages as they pass through Exchange Online. Each record shows the sender, recipient, subject, message ID, size, source IP and delivery status (delivered, quarantined, failed). Administrators use it to investigate mail flow and email security events.

## This pack includes:

Data normalization capabilities:
  * Rules for parsing and modeling O365 MessageTrace logs that are ingested via the HTTP Collector into Cortex XSIAM.
    * The ingested O365 MessageTrace logs can be queried in XQL Search using the *`o365_messagetrace_raw`* dataset.

## Supported log categories
| Category                    | Category Display Name                 |
|:----------------------------|:--------------------------------------|
| email_trace                 | Email Message Trace                   |

***

## Data Collection

### O365 MessageTrace side
1. In the Microsoft Entra admin center, register an application.
2. Grant the application the Microsoft Graph / Exchange Online message trace read permissions, and grant admin consent.
3. Create a client secret for the application.
4. Set up a forwarder (for example, a script or integration) that polls the message trace API and posts the JSON results to the Cortex XSIAM HTTP collector URL. Use the collector token as the Authorization header.

For more information see the official O365 MessageTrace documentation.

### Cortex XSIAM side - Custom - HTTP based Collector

1. Navigate to **Settings** → **Data Sources** → **Add Data Source**.
2. If you have already configured a **Custom - HTTP based Collector**, select the **3 dots**, and then select **+ Add New Instance**. If not, select **+ Add Data Source**, search for "http" and then select **Connect**.
3. Set the following values:

    | Parameter     | Value                               |
    |:--------------|:------------------------------------|
    | `Name`        | O365 MessageTrace Logs.             |
    | `Compression` | Select the desired compression.     |
    | `Log Format`  | Select the relevant log format.     |
    | `Vendor`      | Enter o365.                         |
    | `Product`     | Enter messagetrace.                 |

4. Creating a new HTTP Log Collector will allow you to generate a unique token — save it for later.
5. Click the 3 dots next to the newly created instance and copy the API URL.

For more information, see this [doc](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Set-up-an-HTTP-Log-Collector-to-Receive-Logs).

</~XSIAM>
