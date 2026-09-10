# Imperva Incapsula (Cloud WAF)

This pack includes Cortex XSIAM content.

<~XSIAM>

## Configuration on Server Side

To setup a real-time SIEM log integration via AWS S3 push, follow the **Set up log integration** [process](https://docs.imperva.com/bundle/cloud-application-security/page/settings/log-integration.htm).

### Collection via AWS S3

To create or configure Incapsula log collection via S3, use the information described [here](https://cortex-docs.paloaltonetworks.com/cortex-xsiam/configure-cortex-xsiam/cortex-xsiam-data-sources/vendor-specific-data-sources-and-connectors/amazon/amazon-s3/ingest-network-flow-logs-from-amazon-s3).

You can configure the AWS S3 collector:

1. Navigate to **Settings** > **Data Sources** > **Add Data Source** (Optional) > **Amazon S3**.
2. Make sure to add the following values to the configuration:
   - Log Type - Generic
   - Log Format - CEF
   - Vendor - Auto-Detect
   - Product - Auto-Detect
</~XSIAM>
