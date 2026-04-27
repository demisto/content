<~XSIAM>

## Overview

The network monitoring and diagnostic service in Microsoft Azure.
Providing tools to monitor, diagnose, and gain insights into network traffic and performance across Azure resources.
Key features include packet capture, connection troubleshooting, NSG flow logs, Network Traffic Analytics (NTA) flow logs, VNet flow logs, IP flow verification, and network topology visualization.

**Pay Attention**
This pack contains a beta Modeling Rule, which lets you process Network Traffic Analytics (NTA) logs to XDM fields.
Since the Modeling Rule's NTA logs mapping is considered as beta, it might not contain some of the fields that are available from the logs.
We appreciate your feedback on the quality and usability of the Modeling Rule to help us identify issues, fix them, and continually improve.

## This pack includes

Data normalization capabilities:

* Modeling Rule XDM mapping for NSG Flow Logs that are ingested via the [Azure Network Watcher](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-network-flow-logs-from-Microsoft-Azure-Network-Watcher) integration on Cortex XSIAM.
* Modeling Rule XDM mapping for NTA Flow Logs that are ingested via the [Azure Event Hub](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-Logs-from-Microsoft-Azure-Event-Hub?tocId=kdBiMvtdaJTAWsaoShdYHQ) integration on Cortex XSIAM.
* Parsing Rule timestamp ingestion.
  * The ingested Azure Flow Logs can be queried in XQL Search using the **msft_azure_flowlogs_raw** dataset,
  for the **NTAIpDetails**, **NTATopologyDetails** and **NetworkSecurityGroupFlowEvent** log types.

## Supported log categories

| Log Type                    | Display Name                 |
|:----------------------------|:--------------------------------------|
| [NSG Flow Logs](https://learn.microsoft.com/en-us/azure/network-watcher/nsg-flow-logs-overview?tabs=Americas)  | Network Security Group Flow Event                            |
| [Network Traffic Analytics Flow Logs](https://learn.microsoft.com/en-us/azure/network-watcher/traffic-analytics?tabs=Americas)  |  NTA*                          |

### Supported Timestamp Formats

All of the supported log types support timestamp ingestion for the format **%Y-%m-%dT%H:%M:%E*SZ**.

* For NSG flow logs ingestion, timestamp parsing is done in the order of the following fields: startTime, time.
* For NTA flow logs ingestion, timestamp parsing is with the following fields:
  * For NTAIpDetails, timestamp parsing is according to the FlowIntervalStartTime.
  * For NTATopologyDetails, timestamp parsing is done in the order of the following fields: TimeProcessed, TimeGenerated.

***

## Data Collection

### NSG Flow Logs

In order to send NSG Flow log to XSIAM, enable the Azure Network Watcher integration.
For more information, see [Ingest network flow logs from Microsoft Azure Network Watcher](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-network-flow-logs-from-Microsoft-Azure-Network-Watcher).

### NTA Flow Logs

In order to send NTA Flow Logs to XSIAM, enable the Azure Event Hub integration.
For more information, see [Ingest Logs from Microsoft Azure Event Hub](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-Logs-from-Microsoft-Azure-Event-Hub?tocId=kdBiMvtdaJTAWsaoShdYHQ).

Make sure the following fields are configured correctly for the integration:

| Field                    | Value                 |
|:----------------------------|:--------------------------------------|
| Log Format  | Raw                            |
| Vendor  |  MSFT                          |
| Product  |  Azure                          |

</~XSIAM>
