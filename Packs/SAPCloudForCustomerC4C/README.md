## What does this pack do?

The SAP Cloud for Customer (C4C) integration facilitates the collection of audit events directly from your SAP C4C instance. It enables security teams to monitor user activities and system changes by fetching relevant event data for analysis and incident response.

#### This includes

- Efficient Pagination: Supports client-side pagination with $top and $skip parameters to handle large datasets efficiently (up to 1,000 records per page).
- Customizable Fetch Limit: Allows setting a maximum number of audit events to fetch per run (defaulting to 10,000).

### Configuration Parameters

When setting up an instance of this integration, the following parameters are available:

Server URL: (Required) The base URL of your SAP C4C instance.

User name: (Required) The username for API authentication.

Password: (Required) The password for API authentication.

Report ID: (Required) The specific ID of the C4C analytics report to fetch events from.

Fetch events: (Optional) A checkbox to enable or disable the event collection process.

Maximum number of audit events per fetch: (Optional) Defines the maximum number of events to retrieve in a single fetch run. Defaults to 10,000.
