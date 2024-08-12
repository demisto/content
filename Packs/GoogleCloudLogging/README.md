## What does this pack do

The Google Cloud Logging Cortex <~XSOAR>XSOAR</~XSOAR><~XSIAM>XSIAM</~XSIAM> pack helps users to centralize all their GCP logs in a single location, making it easier to troubleshoot issues and gain insights from their data: 

- The *Google Cloud Logging Integration* enables you to retrieve selected log entries that originated from a project/folder/organization/billing account. See the [Google Cloud Logging integration documentation](https://xsoar.pan.dev/docs/reference/integrations/google-cloud-logging) for additional details.   
<~XSIAM>
- The *Google Cloud Logging Cortex Data Modeling (XDM) Rule* normalizes [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit) and [Google Cloud DNS Query Logs](https://cloud.google.com/dns/docs/monitoring#dns-log-record-format) that are ingested via the [Google Cloud Platform Pub/Sub Data Source](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-logs-and-data-from-a-GCP-Pub/Sub?tocId=RyZP~~W~YWbOPGKAClIQHg) to the [XDM Schema](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-Data-Model-Schema-Guide/Introduction), and the *Google Cloud Logging Parsing Rule* sets the [*`_time`*](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-Data-Model-Schema-Guide/_time) system field of the ingested logs with their corresponding timestamps. 
</~XSIAM>

<~XSIAM>
### Remarks
- When configuring a [sink](https://cloud.google.com/logging/docs/export/configure_export_v2#creating_sink) to route Google Cloud logs to the [Pub/Sub service](https://cloud.google.com/pubsub/docs/pubsub-basics) as described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Logs-and-Data-from-a-GCP-Pub/Sub?tocId=q2ZnSo90ZmO~6aLgts8g5g), you may wish to create an inclusion filter to include only a subset of the logs. See filter examples [here](https://cloud.google.com/logging/docs/export/configure_export_v2#filter-examples) and samples below: 
  -  Filter for including only [Google Cloud Audit Logs](https://cloud.google.com/logging/docs/audit):
  ```
     logName:"cloudaudit.googleapis.com"
  ```
  -  Filter for including only [Google Cloud DNS Query Logs](https://cloud.google.com/dns/docs/monitoring#dns-log-record-format):
  ```
    log_id("dns.googleapis.com/dns_queries") 
  ```
- For auditing [Data Access Audit Logs](https://cloud.google.com/logging/docs/audit#data-access), you may need to explicitly enable the requested Google Cloud services. See [Enable Data Access audit logs](https://cloud.google.com/logging/docs/audit/configure-data-access) for additional details.  
</~XSIAM>