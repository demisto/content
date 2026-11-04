# Sprinklr Event Collector

Collects Sprinklr Reporting API activity into Cortex XSIAM and provides investigation and guarded response commands. Authentication uses OAuth 2.0 Client Credentials and is handled automatically by the integration.

The stable scheduled collector uses persistent checkpoints and Sprinklr `data.hasMore` pagination. Events are sent with vendor `Sprinklr` and product `Sprinklr`, parsed into `sprinklr_sprinklr_raw`, and can be normalized by the included Sprinklr Modeling Rule.

State-changing Governance and SCIM commands require `confirm=yes`.
