## Azure Firewall Pack
Azure Firewall is a cloud-native and intelligent network firewall security service that provides breed threat protection for cloud workloads running in Azure. It's a fully stateful, firewall as a service, with built-in high availability and unrestricted cloud scalability.
This pack contains an integration with a main goal to manage Azure Firewall security service.

## What does this pack do

The Azure Firewall pack contains the following: 
* Integration capabilities:
  * Retrieve, delete firewalls. 
  * Create, delete and retrieve firewall rule collections.
  * Create, delete and retrieve firewall network rules.
  * Create, delete and retrieve firewall policies.
  * Create, delete and retrieve firewall IP groups.
  * Retrieve firewall service tag. 
* Data normalization capabilities: 
  * Rules for parsing and modeling [Azure Firewall Resource Logs](https://learn.microsoft.com/en-us/azure/firewall/monitor-firewall-reference#resource-logs) that are ingested via the [Azure Event Hub data source](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-logs-from-Microsoft-Azure-Event-Hub?tocId=kdBiMvtdaJTAWsaoShdYHQ) on Cortex XSIAM. 
    * The ingested Azure firewall resource logs can be queried in XQL Search using the *`msft_azure_firewall_raw`* dataset. 
    * Supported log categories:

    | Category                       | Category Display Name |
    | :----------------------------- | :------- | 
    | AZFWApplicationRule            | Azure Firewall Application Rule|
    | AZFWApplicationRuleAggregation | Azure Firewall Application Rule Aggregation (Policy Analytics)|
    | AZFWDnsQuery                   | Azure Firewall DNS query|
    | AZFWFatFlow                    | Azure Firewall Fat Flow Log|
    | AZFWFlowTrace                  | Azure Firewall Flow Trace Log|
    | AZFWFqdnResolveFailure         | Azure Firewall FQDN Resolution Failure|
    | AZFWIdpsSignature              | Azure Firewall IDPS Signature|
    | AZFWNatRule                    | Azure Firewall Nat Rule|
    | AZFWNatRuleAggregation         | Azure Firewall Nat Rule Aggregation (Policy Analytics)|
    | AZFWNetworkRule                | Azure Firewall Network Rule|
    | AZFWNetworkRuleAggregation     | Azure Firewall Network Rule Aggregation (Policy Analytics)|
    | AZFWThreatIntel                | Azure Firewall Threat Intelligence|