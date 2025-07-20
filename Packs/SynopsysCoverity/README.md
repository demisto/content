# Synopsys Coverity

This pack includes XSIAM parsing and modeling rules (XDM schema) for Synopsys Coverity Enhanced Usage Logging.

## Configuration on Server Side

Coverity does not support native log forwarding (e.g., Syslog). Instead, it writes enhanced usage logs to local files on the host filesystem.

    1. Ensure that Coverity is configured to generate Enhanced Usage Logs.

    2. The log files are typically written under the Coverity installation directory, usually in: `<install_dir>\logs`

    3. Verify that the logs are being written in **JSON format** (e.g., coverity_usage-*.log).

If logs are not found in the default path, refer to [Coverity Enhanced Usage Logging documentation](https://documentation.blackduck.com/bundle/coverity-docs/page/coverity-platform/topics/enhanced_usage_logging.html) for exact location and format details.

### Filebeat Collection

In order to collect the logs and forward them to Cortex XSIAM, use the following collector:

#### XDRC (XDR Collector)

You will configure a profile for the XDR Collector and assign the correct vendor and product values.

To set up the collector, follow the instructions outlined in the official [Cortex XSIAM XDR Collector documentation](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b).

The dataset name will be:

`synopsys_coverity_raw`

##### Filebeat Configuration File

Paste the following YAML configuration in the Filebeat Configuration File section of the relevant XDR Collector profile:

```
filebeat.inputs:
- type: filestream
  enabled: true
  paths:
    - <install_dir>\logs\*.log
  processors:
    - add_fields:
        fields:
          vendor: synopsys
          product: coverity
```

**Note:**
If your Coverity logs are stored in a different directory, make sure to update the paths field accordingly.
