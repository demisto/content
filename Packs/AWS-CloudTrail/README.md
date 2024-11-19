<~XSIAM>
## What does this pack do

The AWS CloudTrail pack contains the following: 
* Integration for interacting with a trail on AWS via an automation (Playbooks, Playground, etc.). See the [*AWS - CloudTrail*](https://xsoar.pan.dev/docs/reference/integrations/aws---cloud-trail#configure-aws---cloudtrail-on-cortex-xsoar) integration docs for additional details.
* Data normalization rules for parsing and modeling [*AWS CloudTrail Audit Logs*](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html) that are ingested into the *`amazon_aws_raw`* dataset via the *Amazon S3* data source on Cortex XSIAM. See [Ingest audit logs from AWS Cloud Trail](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-audit-logs-from-AWS-Cloud-Trail) for configuration details. When configuring the Amazon S3 data source on Cortex XSIAM, select the **Audit Logs** log type: 
![Amazon S3 Data Source Log Type Selection](https://raw.githubusercontent.com/demisto/content/3d7aa25b8df1d343beb17f67afce837050a180f4/Packs/AWS-CloudTrail/doc_files/Amazon_S3_DataSource_Config.png)

</~XSIAM>