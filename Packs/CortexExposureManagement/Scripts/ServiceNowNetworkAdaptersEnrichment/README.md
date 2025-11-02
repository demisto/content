This script resolves the owner and related configuration items of a network adapter by searching the ServiceNow CMDB network adapter table using a specified IP address.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| ip_address | The ip address of the network adapters to look for. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CortexExposureManagement.ServiceNowEnrichment.summary | A brief summary of the results of enrichment. | string |
| CortexExposureManagement.ServiceNowEnrichment.network_adapters.sys_id | The unique system identifier \(Sys ID\) of the network adapter record in ServiceNow. | string |
| CortexExposureManagement.ServiceNowEnrichment.network_adapters.name | The name of the network adapter. | string |
| CortexExposureManagement.ServiceNowEnrichment.network_adapters.ip | The IP address assigned to the network adapter. | string |
| CortexExposureManagement.ServiceNowEnrichment.network_adapters.owner | The display name of the user assigned as the owner of the network adapter. | string |
| CortexExposureManagement.ServiceNowEnrichment.network_adapters.owner_id | The unique Sys ID of the user assigned to the network adapter. | string |
| CortexExposureManagement.ServiceNowEnrichment.network_adapters.related_configuration_item_name | The display name of the related configuration item \(CI\) associated with this network adapter. | string |
| CortexExposureManagement.ServiceNowEnrichment.network_adapters.related_configuration_item_id | The Sys ID of the related configuration item associated with this network adapter. | string |
| CortexExposureManagement.ServiceNowEnrichment.network_adapters.url | A direct URL link to the network adapter record in the ServiceNow instance. | string |
| CortexExposureManagement.ServiceNowEnrichment.related_configuration_items.sys_id | The unique system identifier \(Sys ID\) of the related configuration item \(CI\) record in ServiceNow. | string |
| CortexExposureManagement.ServiceNowEnrichment.related_configuration_items.name | The name of the related configuration item. | string |
| CortexExposureManagement.ServiceNowEnrichment.related_configuration_items.ip | The IP address associated with the configuration item. | string |
| CortexExposureManagement.ServiceNowEnrichment.related_configuration_items.owner | The display name of the user assigned as the owner of the configuration item. | string |
| CortexExposureManagement.ServiceNowEnrichment.related_configuration_items.owner_id | The unique Sys ID of the user assigned to the configuration item. | string |
| CortexExposureManagement.ServiceNowEnrichment.related_configuration_items.hostname | The hostname of the configuration item. | string |
| CortexExposureManagement.ServiceNowEnrichment.related_configuration_items.os | The operating system running on the configuration item. | string |
| CortexExposureManagement.ServiceNowEnrichment.related_configuration_items.os_version | The version of the operating system running on the configuration item. | string |
| CortexExposureManagement.ServiceNowEnrichment.related_configuration_items.ci_class | The ServiceNow CI class that defines the type of the configuration item \(e.g., Server, Application, Network Gear\). | string |
| CortexExposureManagement.ServiceNowEnrichment.related_configuration_items.use | The intended purpose or usage of the configuration item as recorded in ServiceNow. | string |
| CortexExposureManagement.ServiceNowEnrichment.related_configuration_items.url | A direct URL link to the configuration item record in the ServiceNow instance. | string |
