<~XSIAM>
## Azure App Service Pack

### This pack includes:

Data normalization capabilities: 
  * Rules for parsing and modeling [Azure App Service Resource Logs](https://learn.microsoft.com/en-us/azure/app-service/monitor-app-service-reference#resource-logs) that are ingested via the [Azure Event Hub data source](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Logs-from-Microsoft-Azure-Event-Hub) on Cortex XSIAM. 
    * When configuring the Azure Event Hub data source, mark the following checkbox under the *Enhanced Cloud Protection* section:
      * **`Use audit logs in analytics`** 
    * The ingested Azure app service resource logs can be queried in XQL Search using the *`msft_azure_app_service_raw`* dataset. 

    
### Supported log categories

| Category                                                                     | Category Display Name                 |
|:-------------------------------------------------------------------------|:--------------------------------------| 
| [AppServiceHTTPLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/appservicehttplogs)                             | App Service HTTP Logs                 |
| [AppServiceConsoleLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/appserviceconsolelogs)                       | App Service Console Logs              |
| [AppServiceAppLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/appserviceapplogs)                               | App Service App Logs                  |
| [AppServiceIPSecAuditLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/appserviceipsecauditlogs)                 | App Service IPSec Audit Logs          |
| [AppServicePlatformLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/appserviceplatformlogs)                     | App Service Platform Logs             |
| [AppServiceAntivirusScanAuditLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/appserviceantivirusscanauditlogs) | App Service Antivirus Scan Audit Logs |
| [AppServiceFileAuditLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/appservicefileauditlogs)                   | App Service File Audit Logs           |
| [FunctionAppLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/functionapplogs)                                   | Function App Logs                     |
| [AppServiceAuditLogs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/appserviceauditlogs)                           | App Service Audit Logs                |
| [WorkflowRuntime](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/logicappworkflowruntime)                           | Workflow Runtime                      |
| AppServiceEnvironmentPlatformLogs            | App Service Environment Platform Logs |


</~XSIAM>