## Azure Kubernetes Services (AKS)
<~XSIAM>

### This pack includes:
- Log Normalization - XDM mapping for key event types.
- Log timestamp ingestion.

**Pay Attention:**
This pack should only be installed after installing the Azure Logs pack.

### Supported Event Types:
- cluster-autoscaler
- cloud-controller-manager
- kube-audit
- kube-audit-admin
- kube-apiserver
- kube-controller-manager
- kube-scheduler
- csi-snapshot-controller
- csi-azuredisk-controller
- csi-azurefile-controller
- SoftwareUpdateProfile
- SoftwareUpdates
- guard

### Supported Timestamp Formats:
For *msft_azure_aks_raw*, timestamp ingestion is according to one of the following fields-
- requestreceivedtime
- TimeGenerated
- properties.log.requestReceivedTimestamp

In UTC time zone YYYY-mm-ddTHH:MM:SS.ssssZ format. E.g; 2025-02-04T11:23:29.0324070Z

***

## Data Collection
To configure Microsoft Azure AKS to send logs to Cortex XSIAM, follow the below steps.

### Prerequisites
- Create an **Azure event hub**. For more information, refer to Microsoft's official [documentation](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-create).
- Make sure that you have at least a Security Administrator role.
- For more information, refer to Microsoft's official [documentation](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-stream-logs-to-event-hub).

### Cortex XSIAM side
To connect Cortex XSIAM to the Azure Event Hub, follow the below steps.

#### Azure Event Hub Collector
1. Navigate to **Settings** &rarr; **Data Sources**.
2. If you have already configured an **Azure Event Hub Collector**, select the **3 dots**, and then select **+ Add New Instance**. If not, select **+ Add Data Source**, search for "Azure Event Hub" and then select **Connect**.
3. Fill in the attributes based on the Azure Event Hub you streamed your data to.
4. Leave the **Use audit logs in analytics** checkbox selected, unless you were told otherwise.

More information can be found [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Logs-from-Microsoft-Azure-Event-Hub?tocId=yjPDSlvRYtlNncGBLHOzvw).

</~XSIAM>