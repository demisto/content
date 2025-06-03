# Imperva Incapsula (Cloud WAF)

This pack includes Cortex XSIAM content.

<~XSIAM>

## Configuration on Server Side

To setup a real-time SIEM log integration via AWS S3 push, follow the **Set up log integration** [process](https://docs.imperva.com/bundle/cloud-application-security/page/settings/log-integration.htm).

### Collection via AWS S3

To create or configure Incapsula log collection via S3, use the information described [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Ingest-Network-Flow-Logs-from-Amazon-S3).

You can configure the AWS S3 collector:

1. Navigate to **Settings** > **Data Sources** > **Add Data Source** (Optional) > **Amazon S3**.
2. Make sure to add the following values to the configuration:
   - Log Type - Generic
   - Log Format - CEF
   - Vendor - incapsula
   - Product - siemintegration
</~XSIAM>
