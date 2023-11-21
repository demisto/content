This content pack provides the Feed Hello World integration for getting started with your feed integration and the Hello World integration that imports events as incidents.

The purpose of this pack is to learn how to build a Cortex XSOAR content pack.

## What does this pack do?

- Returns domain information and reputation.
- Retrieves alert extra data by ID.
- Retrieves scan status in context or as a file (default) for a scan.
- Starts a scan on an asset.
- Retrieves scan status for one or more scan IDs.
- Searches HelloWorld alerts.
- Updates the status for an alert.
- Returns IP information and reputation.

As part of this pack, you get an out-of-the-box automation, classifiers, incident fields and a Hello World layout. In addition there are two playbooks:
- A playbook that will handle the alerts coming from the Hello World service.
- A playbook that simulates a vulnerability scan using the "HelloWorld" sample integration. It's used to demonstrate how to use the GenericPolling mechanism to run jobs that take several seconds or minutes to complete.