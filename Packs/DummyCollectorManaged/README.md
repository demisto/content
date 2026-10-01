## Dummy Collector Managed

This pack contains a dummy Cortex XSIAM event collector that generates fake events without calling any external API. This is the MANAGED variant (managed-content pack) of Dummy Collector Regular: it uses a different integration ID but shares the same modeling rule, parsing rule, and dataset. It is intended as a test fixture for managed-content pipelines.

### What does this pack contain?

- **Dummy Managed Event Collector** integration - generates fake events (login, logout, file access, configuration change) and sends them to Cortex XSIAM.
- **Dummy Collector Parsing Rule** - sets the `_time` field of ingested events from their `created_time` field.
- **Dummy Collector Modeling Rule** - maps the raw events in the `dummy_collector_raw` dataset to the Cortex Data Model (XDM).

### Dataset

Events are ingested into the `dummy_collector_raw` dataset (vendor `dummy`, product `collector`).
