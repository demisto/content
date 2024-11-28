<~XSIAM>

### This pack includes:
- Log Normalization - XDM mapping for key event types.

### Supported Event Types:
- ApplicationGatewayAccessLog
- ApplicationGatewayFirewallLog

### Supported Timestamp Formats:
For *msft_azure_waf_raw*, timestamp ingestion is according to the **timeStamp** field in UTC (00:00) time zone.

***

## Data Collection
To configure Microsoft Azure WAF to send logs to Cortex XSIAM, follow the below steps.

### Prerequisites
- Create an **Azure event hub**. For more information, refer to Microsoft's official [documentation](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-create).
- Make sure that you have at least a Security Administrator role.

### Stream logs to an event hub
1. Sign in to the **Microsoft Entra admin center**.
2. Navigate to **Identity** &rarr; **Monitoring & health** &rarr; **Diagnostic settings**.
3. Select **+ Add diagnostic setting** to create a new integration or select **Edit setting** for an existing integration.
4. Enter a **Diagnostic setting name**. If you're editing an existing integration, you can't change the name.
5. Select the log categories that you want to stream. Refer to the **Log Normalization** section for the supported log categories for normalization.
6. Select the **Stream to an event hub** checkbox.
7. Select the Azure subscription, Event Hubs namespace, and optional event hub where you want to route the logs.

For more information, refer to Microsoft's official [documentation](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-stream-logs-to-event-hub).

### Cortex XSIAM side
To connect Cortex XSIAM to the Azure Event Hub, follow the below steps.

#### Azure Event Hub Collector
1. Navigate to **Settings** &rarr; **Data Sources**.
2. If you have already configured an **Azure Event Hub Collector**, select the **3 dots**, and then select **+ Add New Instance**. If not, select **+ Add Data Source**, search for "Azure Event Hub" and then select **Connect**.
3. Fill in the attributes based on the Azure Event Hub you streamed your data to.
4. Leave the **Use audit logs in analytics** checkbox selected, unless you were told otherwise.

More information can be found [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Logs-from-Microsoft-Azure-Event-Hub?tocId=yjPDSlvRYtlNncGBLHOzvw).

![MicrosoftEntraID_Azure_Event_Hub](../../doc_files/MicrosoftEntraID_Azure_Event_Hub.png)

</~XSIAM>