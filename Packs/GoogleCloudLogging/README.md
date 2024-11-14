## What does this pack do

The Google Cloud Logging Cortex <~XSOAR>XSOAR</~XSOAR><~XSIAM>XSIAM</~XSIAM> pack helps users to centralize all their GCP logs in a single location, making it easier to troubleshoot issues and gain insights from their data.

### Google Cloud Logging Integration
The *Google Cloud Logging Integration* enables you to retrieve selected log entries that originated from a project/folder/organization/billing account. See the [Google Cloud Logging integration documentation](https://xsoar.pan.dev/docs/reference/integrations/google-cloud-logging) for additional details.   


<~XSIAM>
### Google Cloud Logging SIEM Content
The SIEM content includes *Cortex Data Modeling (XDM) Rules* and *Parsing Rules* which are applied on [*Google Cloud Audit Logs*](https://cloud.google.com/logging/docs/audit) and [*Google Cloud DNS Query Logs*](https://cloud.google.com/dns/docs/monitoring#dns-log-record-format) that are ingested into the *`google_cloud_logging_raw`* and *`google_dns_raw`* datasets (respectively) via the *Google Cloud Platform Pub/Sub* data source on Cortex XSIAM. See [*Ingest Logs and Data from a GCP Pub/Sub*](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-logs-and-data-from-a-GCP-Pub/Sub?tocId=RyZP~~W~YWbOPGKAClIQHg) for additional details.

#### Remarks
- When configuring a [sink](https://cloud.google.com/logging/docs/export/configure_export_v2#creating_sink) to route Google Cloud logs to the [Pub/Sub service](https://cloud.google.com/pubsub/docs/pubsub-basics) as described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-logs-and-data-from-a-GCP-Pub/Sub?tocId=RyZP~~W~YWbOPGKAClIQHg), you may wish to create an inclusion filter to include only a subset of the logs. See filter examples [here](https://cloud.google.com/logging/docs/export/configure_export_v2#filter-examples) and samples below: 
  -  Sample filter for including only [*Google Cloud Audit Logs*](https://cloud.google.com/logging/docs/audit):
  ```
     logName:"cloudaudit.googleapis.com"
  ```
  -  Sample filter for including only [*Google Cloud DNS Query Logs*](https://cloud.google.com/dns/docs/monitoring#dns-log-record-format):
  ```
    log_id("dns.googleapis.com/dns_queries") 
  ```
- For auditing [*Data Access Audit Logs*](https://cloud.google.com/logging/docs/audit#data-access), you may need to explicitly enable the requested Google Cloud services. See [*Enable Data Access audit logs*](https://cloud.google.com/logging/docs/audit/configure-data-access) for additional details.  

</~XSIAM>