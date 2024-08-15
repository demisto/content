When migrating to Infrastructure-as-a-Service (IaaS), you are responsible for securing your environment. 
This means you need to secure your network and services. 
These processes were normally handled by your cloud provider within a Platform-as-a-Service (PaaS) or Software-as-a-Service (SaaS) environment. 
Azure Security Center provides threat protection for data centers within both cloud workloads and on-premises. 

## What does this pack do?
- Apply security policies across your workloads.
- Limit your exposure to threats.
- Detect and respond to attacks.


# License information
Must be enabled on at least 1 Azure subscription.

<~XSIAM>

### This pack includes:
Log Normalization - XDM mapping.

### Supported Event Types:
Security Alerts

### Supported Timestamp Formats:
MMM DD YYYY HH:MM:SS (UTC)


***

## Data Collection

Cortex XSIAM supports two methods to fetch alerts from Microsoft Defender for Cloud:
- Microsoft Defender for Cloud collector (API Collection).
- Azure Event Hub.

### Microsoft Defender for Cloud collector 

This collection method is more relevant in cases where the number of subscriptions is low, as each integration's instance refers to one subscription.

For more information on how to configure this integration, refer to the integration's docs:

1. Navigate to **settings** &rarr; **Automation & Feed Integrations**.

2. Search for **Microsoft Defender for Cloud**.
3. Click **+ Add instance**.


### Azure Event Hub 
This collection method is more relevant in cases where the number of subscriptions is high, and you want to stream alerts at the tenant level.
Nevertheless, it supports alerts streaming at the subscription level as well.

#### Prerequisites
- Create an **Azure event hub**. For more information, refer to Microsoft's official [documentation](https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-create).
- Make sure that you have permissions for the root management group.

#### Stream alerts with Continuous Export to Event Hub

Refer to the following links for detailed instructions:

- At the [subscription level](https://learn.microsoft.com/en-us/azure/defender-for-cloud/continuous-export). 
- At the [tenant level](https://learn.microsoft.com/en-us/azure/defender-for-cloud/continuous-export-azure-policy).

More information can be found [here](https://learn.microsoft.com/en-us/azure/defender-for-cloud/export-to-siem#stream-alerts-with-continuous-export).

### Cortex XSIAM side
To connect Cortex XSIAM to the Azure Event Hub, follow the below steps.

#### Azure Event Hub Collector
1. Navigate to **Settings** &rarr; **Data Sources**.
2. If you have already configured an **Azure Event Hub Collector**, select the **3 dots**, and then select **+ Add New Instance**. If not, select **+ Add Data Source**, search for "Azure Event Hub" and then select **Connect**.
3. Fill in the attributes based on the Azure Event Hub you streamed your data to.
4. Uncheck the **Use audit logs in analytics** checkbox.
5. Set the below values:
   - Vendor - microsoft
   - Product - defender_for_cloud
   - Log Format - JSON

More information can be found [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Logs-from-Microsoft-Azure-Event-Hub?tocId=yjPDSlvRYtlNncGBLHOzvw).

</~XSIAM>