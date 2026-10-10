## Dummy Collector Regular

This pack contains a dummy Cortex XSIAM event collector that generates fake events without calling any external API. It is intended as a test fixture for managed-content pipelines.

### What does this pack contain?

- **Dummy Regular Event Collector** integration - generates fake events (login, logout, file access, configuration change) and sends them to Cortex XSIAM.
- **Dummy Collector Parsing Rule** - sets the `_time` field of ingested events from their `created_time` field.
- **Dummy Collector Modeling Rule** - maps the raw events in the `dummy_collector_raw` dataset to the Cortex Data Model (XDM).

### Dataset

Events are ingested into the `dummy_collector_raw` dataset (vendor `dummy`, product `collector`).
