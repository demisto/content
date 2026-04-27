## Overview

This pack includes Cortex XSIAM content.
Salesforce is a company that makes cloud-based software designed to help businesses find more prospects, close more deals, and wow customers with amazing service.

<~XSIAM>

## This pack includes

Data normalization capabilities:

* Rules for parsing and modeling Salesforce logs that are ingested via the event collector into Cortex XSIAM.

### Supported timestamp formats

* `%Y-%m-%dT%H:%M:%E3SZ`: Supported UTC format for Event Log File and Login events.
* `%Y-%m-%dT%H:%M:%E3S%Z`: Supported time zone (+HHMM or -HHMM) for audit events.
* `%Y-%m-%dT%H:%M:%E3SZ`: Supported UTC format for Salesforce Realtime event collector.

## Data Collection

The Cortex XSIAM data collector can collect Audit Trail and Security Monitoring event logs from Salesforce.com.

To configure the collector for Salesforce, follow the XDR documentation [here](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Ingest-logs-and-data-from-Salesforce.com).
</~XSIAM>
