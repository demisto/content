<~XSIAM>  


# Microsoft Entra ID

## What does this pack do?
### Log Normalization - One Data Model
This pack support normalization of the below log categories of Microsoft Entra ID:
1. AuditLogs
2. SignInLogs
3. NonInteractiveUserSignInLogs
4. ServicePrincipalSignInLogs
5. ManagedIdentitySignInLogs
6. ADFSSignInLogs
7. ProvisioningLogs

### Timestamp Parsing
Timestamp parsing relies on 2 fields, which depends on the log category:
1. `properties.activityDateTime`
   1. AuditLogs
   2. ProvisioningLogs
   

2. `properties.activityDateTime`  
   1. SignInLogs
   2. NonInteractiveUserSignInLogs
   3. ServicePrincipalSignInLogs
   4. ManagedIdentitySignInLogs
   5. ADFSSignInLogs

---
## Data Collection

### Entra ID Side
To configure Microsoft Entra ID to send logs to XSIAM, follow the below steps.

#### Prerequisites

1. Create an **Azure event hub**. For more information, refer to Microsoft's official [documetaion](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-create).
2. Make sure that you have at least Security Administrator role.

#### Stream logs to an event hub
1. Sign in to the **Microsoft Entra admin center**.
2. Navigate to **Identity** &rarr; **Monitoring & health** &rarr; **Diagnostic settings**.
3. Select **+ Add diagnostic setting** to create a new integration or select **Edit setting** for an existing integration.
4. Enter a **Diagnostic setting name**. If you're editing an existing integration, you can't change the name.
5. Select the log categories that you want to stream. Refer to the **Log Normalization** section for the supported log categories for normalization.
6. Select the Stream to an event hub check box.
7. Select the Azure subscription, Event Hubs namespace, and optional event hub where you want to route the logs.

For more information, refer to Microsoft's official [documetaion](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-stream-logs-to-event-hub?tabs=splunk).

### XSIAM side
To connect XSIAM to the Azure Event Hub, follow the below steps.

#### Azure Event Hub Collector
1. Navigate to **Settings** &rarr; **Data Sources**.
2. If you have already configured an **Azure Event Hub Collector**, select the **3 dots**, and then select **+ Add New Instance**. If not, select **+ Add Data Source**, search for "Azure Event Hub" and then select **Connect**.
3. Fill in the attributes based on the Azure Event Hub you streamed your data to.
4. Leave the **Use audit logs in analytics** checkbox selected, unless you were told otherwise.

More information can be found [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Logs-from-Microsoft-Azure-Event-Hub?tocId=yjPDSlvRYtlNncGBLHOzvw).

query

</~XSIAM>





