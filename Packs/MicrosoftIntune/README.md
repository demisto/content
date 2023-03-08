# Microsoft Intune

This pack includes Cortex XSIAM content.

Note: The logs will be stored in the dataset named *msft_azure_raw*. 
To filter a query to focus only on Microsoft Intune logs, use the following filters:
- In XQL queries, use "_collector_name".
- In Datamodel queries, use "xdm.observer.name".

## Collect Events from Vendor

In order to use the collector, you need to use the following option:

  - [External Data Ingestion (External Data Ingestion)](#external-data-ingestion)


To collect logs from Microsoft Intune, use the information described [here](https://learn.microsoft.com/en-us/mem/intune/fundamentals/review-logs-using-azure-monitor) to configure log streaming from Microsoft Intune to Azure Event Hub.


### Azure Event Hub Collector (External Data Ingestion)

To create or configure the Azure Event Hub collector (to collect the logs we've sent to Azure Event Hub), use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Logs-from-Microsoft-Azure-Event-Hub).