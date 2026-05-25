This content pack runs queries on Splunk servers and fetches events from both Splunk Enterprise Security (ES) and non-ES environments.

## What does this pack do?

This pack includes two integrations designed for different Splunk ES versions:

### SplunkPy

The primary integration for Splunk ES versions up to 8.1, which automatically fetches notable events from Splunk along with their context data. The integration provides the analyst with comprehensive incident information directly in the XSOAR/XSIAM console.

### SplunkPy v2

Designed for Splunk ES version 8.2 and higher, supporting the new Splunk Finding Events architecture.

Using the commands in these integrations, you can leverage the Splunk API capabilities, such as:

- Running SPL (Splunk Search Processing Language) queries
- Managing events
- Working with KV store collections (create, search, update, delete)
- Enriching events with Asset, Identity, and Drilldown data
- Managing indexes and submitting events
- Bi-directional mirroring between Splunk and Cortex XSOAR

**Note:**  
When mirroring or fetching incidents between Splunk and Cortex XSOAR, you need to [map Splunk users to Cortex XSOAR users](https://xsoar.pan.dev/docs/reference/integrations/splunk-py#use-cases).
