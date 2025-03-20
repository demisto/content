<~XSIAM>
## Azure Kubernetes Services (AKS)

 ### This pack includes:

Data normalization capabilities: 
  * Rules for parsing and modeling [Azure AKS Resource Logs](https://learn.microsoft.com/en-us/azure/aks/monitor-aks-reference#resource-logs) that are ingested via the [Azure Event Hub data source](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Logs-from-Microsoft-Azure-Event-Hub) on Cortex XSIAM. 
    * When configuring the Azure Event Hub data source, mark the following checkbox under the *Enhanced Cloud Protection* section:
      * **`Use audit logs in analytics`** 
    * The ingested Azure AKS resource logs can be queried in XQL Search using the *`msft_azure_aks_raw`* dataset. 

**Pay Attention:**
This pack should only be installed after installing the Azure Logs pack.

### Supported log categories
| Azure Log Analytics Table                                                        | Category                              | Category Display Name                 |
|:-------------------------------------------------------------------------|:--------------------------------------|:--------------------------------------| 
| [AKSAudit](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aksaudit)                             | kube-audit                 | Kubernetes Audit                 |
| [AKSAuditAdmin](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aksauditadmin)                       | kube-audit-admin              | Kubernetes Audit Admin Logs              |
| [AKSControlPlane](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/akscontrolplane)                               | kube-apiserver                  | Kubernetes API Server                  |
| [AKSControlPlane](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/akscontrolplane)                               | kube-controller-manager                  | Kubernetes Controller Manager                  |	
| [AKSControlPlane](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/akscontrolplane)                               | kube-scheduler                  | Kubernetes Scheduler                  |
| [AKSControlPlane](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/akscontrolplane)                               | cloud-controller-manager                 | Kubernetes Cloud Controller Manager                  |
| [AKSControlPlane](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/akscontrolplane)                               | cluster-autoscaler                 | Kubernetes Cluster Autoscaler                  |
| [AKSControlPlane](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/akscontrolplane)                               | guard                 | Guard                  |	

### Timestamp Ingestion:
For *msft_azure_aks_raw*, timestamp ingestion is according to one of the following fields;
- requestreceivedtime
- TimeGenerated
- properties.log.requestReceivedTimestamp

In UTC time zone YYYY-mm-ddTHH:MM:SS.ssssZ format. E.g; 2025-02-04T11:23:29.0324070Z

</~XSIAM>