# This pack includes

Data normalization capabilities:

    Parsing and modeling rules (XDM schema) for Synopsys Coverity enhanced usage logs that are ingested via File Collector on Cortex XSIAM.

    The ingested Synopsys Coverity logs can be queried in XQL Search using the `synopsys_coverity_raw` dataset.

### Configuration on Server Side

Synopsis Coverity does not support native log forwarding (for example, Syslog). Instead, it writes enhanced usage logs to local files on the host filesystem.

    1. Ensure that Synopsis Coverity is configured to generate enhanced usage logs.
       The log files are typically written under the Synopsis Coverity installation directory, usually under `<install_dir>\logs`
    2. Verify that the logs are being written in **JSON format** (e.g., coverity_usage-*.log).

If logs are not found in the default path, refer to [Coverity Enhanced Usage Logging documentation](https://documentation.blackduck.com/bundle/coverity-docs/page/coverity-platform/topics/enhanced_usage_logging.html) for exact location and format details.

#### Filebeat Collection

In order to collect the logs and forward them to Cortex XSIAM, use the following collector:

##### XDRC (XDR Collector)

You will configure a profile for the XDR Collector and assign the correct vendor and product values.

To set up the collector, follow the instructions outlined in the official [Cortex XSIAM XDR Collector documentation](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b).

###### Filebeat Configuration File

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
If your Synopsis Coverity logs are stored in a different directory, update the path field accordingly.
