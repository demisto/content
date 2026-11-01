<~XSIAM>

### About Zero Networks Segment

Zero Networks Segment is a security platform that automatically enforces zero trust policies across an organization's network. It dynamically segments and controls access to network resources, ensuring that only authorized users and devices can communicate, thereby reducing the attack surface and mitigating potential threats.

### Pack Contents

- `ZeroNetworksSegmentEventCollector` integration - integrates with Zero Networks Segment API to fetch and process audit and network events.
- Log Normalization - XDM mapping for key event types.

### Supported Event Types for Normalization

- Audit Logs
- Network Activity Logs

### Data Collection

You can collect Zero Networks Segment logs in Cortex XSIAM using either of the following methods:

1. **HTTP Event Collector (HEC) push** - Zero Networks pushes the logs directly to a Cortex XSIAM HTTP Log Collector. **This is Zero Networks' recommended best practice for log collection.**
2. **Zero Networks Segment Event Collector integration** - Cortex XSIAM pulls the audit and network activity logs from the Zero Networks Segment API.

#### Option 1: HTTP Event Collector (HEC) - Recommended by Zero Networks

##### Step 1: Configure an HTTP Log Collector in Cortex XSIAM

1. In Cortex XSIAM, navigate to **Settings** > **Data Sources** > **Add Data Source** > **Custom - HTTP based Collector**.
2. Click **Connect** (or **Connect Another Instance**).
3. Configure the following:
   - **Name**: `Zero Networks Segment`
   - **Compression**: `uncompressed`
   - **Log Format**: `JSON`
   - **Vendor**: `zeronetworks`
   - **Product**: `segment`
4. Click **Save & Generate Token**. Copy the generated token and save it in a safe place. You will need it in Step 2.
5. Click the 3 dots next to the new instance and select **Copy API URL**. You will need it in Step 2.

For more information, see [Set up an HTTP log collector to receive logs](https://cortex-docs.paloaltonetworks.com/cortex-xsiam/configure-cortex-xsiam/cortex-xsiam-data-sources/vendor-specific-data-sources-and-connectors/http-log-collector/set-up-an-http-log-collector-to-receive-logs).

##### Step 2: Configure the SIEM integration in the Zero Networks Admin Portal

1. Log in to the Zero Networks Admin Portal.
2. Navigate to **Settings** > **Integrations** > **SIEM**.
3. Select **Add Splunk/Securonix/other HEC Compatible SIEM Systems**.
4. In the configuration window, enter the following Cortex XSIAM details:
   - **HEC URI**: The Cortex XSIAM HTTP Log Collector API URL you copied in Step 1.
   - **Token**: The Cortex XSIAM HTTP Log Collector token you generated in Step 1.
5. Under **Data configuration**, select the checkboxes for the log types you want to export:
   - Network activity
   - RPC activity
   - Identity activity
   - Audit
6. (Optional) Enter the target index for each log type, if your Cortex XSIAM data schema requires it.
7. Click **Add** to save the configuration and start pushing logs.

The logs are ingested into the `zeronetworks_segment_raw` dataset.

**Note:** The modeling rules in this pack were built for events fetched by the Zero Networks Segment Event Collector. They identify the log type using the `source_log_type` field, which the integration adds to each event. Logs pushed through HEC may not include this field, so XDM normalization might not be applied to them.

#### Option 2: Zero Networks Segment Event Collector integration

Configure the `ZeroNetworksSegmentEventCollector` integration instance in Cortex XSIAM to fetch audit and network activity logs from the Zero Networks Segment API. For details, see the integration README.

</~XSIAM>
