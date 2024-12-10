## Azure Firewall Pack

## What does this pack do

The Azure Firewall pack contains the following: 
* Integration capabilities:
  * Retrieve or delete firewalls. 
  * Create, delete and retrieve firewall rule collections.
  * Create, delete and retrieve firewall network rules.
  * Create, delete and retrieve firewall policies.
  * Create, delete and retrieve firewall IP groups.
  * Retrieve firewall service tag. 
* Data normalization capabilities: 
  * Rules for parsing and modeling [Azure Firewall Resource Logs](https://learn.microsoft.com/en-us/azure/firewall/monitor-firewall-reference#resource-logs) that are ingested via the [Azure Event Hub data source](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-logs-from-Microsoft-Azure-Event-Hub) on Cortex XSIAM. 
    * When configuring the Azure Event Hub data source, mark the following checkbox under the *Enhanced Cloud Protection* section:
      * **`Use audit logs in analytics`** 
    * The ingested Azure firewall resource logs can be queried in XQL Search using the *`msft_azure_firewall_raw`* dataset. 
    * Supported log categories:

    | Category                       | Category Display Name |
    | :----------------------------- | :------- | 
    | [AZFWApplicationRule](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azfwapplicationrule) | Azure Firewall Application Rule|
    | [AZFWApplicationRuleAggregation](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azfwapplicationruleaggregation) | Azure Firewall Application Rule Aggregation (Policy Analytics)|
    | [AZFWDnsQuery](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azfwdnsquery) | Azure Firewall DNS query|
    | [AZFWFatFlow](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azfwfatflow) | Azure Firewall Fat Flow Log|
    | [AZFWFlowTrace](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azfwflowtrace) | Azure Firewall Flow Trace Log|
    | [AZFWFqdnResolveFailure](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azfwinternalfqdnresolutionfailure) | Azure Firewall FQDN Resolution Failure|
    | [AZFWIdpsSignature](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azfwidpssignature) | Azure Firewall IDPS Signature|
    | [AZFWNatRule](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azfwnatrule) | Azure Firewall Nat Rule|
    | [AZFWNatRuleAggregation](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azfwnatruleaggregation)| Azure Firewall Nat Rule Aggregation (Policy Analytics)|
    | [AZFWNetworkRule](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azfwnetworkrule) | Azure Firewall Network Rule|
    | [AZFWNetworkRuleAggregation](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azfwnetworkruleaggregation) | Azure Firewall Network Rule Aggregation (Policy Analytics)|
    | [AZFWThreatIntel](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/azfwthreatintel) | Azure Firewall Threat Intelligence|