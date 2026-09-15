This integration collects Command Line Interface (CLI) audit log records from the IBM Storage Scale API. It is engineered for high performance and scalability, using a concurrent fetching mechanism to efficiently ingest large volumes of data from enterprise-level storage environments.

**Important Notes Before Configuration**

To ensure a successful and stable configuration, please review the following prerequisites carefully.

**1. Service Account and Permissions**

It is critical to create a dedicated service account within IBM Storage Scale for this integration. Do not use a personal administrator account. This service account must be assigned the ProtocolAdmin role, which grants the necessary permissions to access the audit log API endpoint.

**2. Non-Expiring Password**

For uninterrupted event collection, it is highly recommended to configure the service account's password to not expire. If the password expires, the integration will fail to authenticate and event collection will stop until the credentials are updated.

**3. High-Performance Collector**

This integration is designed to handle a high throughput of events (10,000+ events per minute). It achieves this by making multiple, simultaneous connections to the API. Please ensure your IBM Storage Scale API server is provisioned to handle this concurrent load.

**4. Configuration in Cortex XSIAM**

When configuring the integration instance, you will need to provide:

The full Server URL for the API, including the https:// prefix and port.

The Credentials for the service account created above.

Enable Fetch events to begin collecting data for ingestion.

Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.
