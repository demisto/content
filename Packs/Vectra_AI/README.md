Vectra® is the leading AI-driven threat detection and response platform for the enterprise.
Only Vectra optimizes AI to detect advanced attacker behaviors across hybrid and multi-cloud environments.
The resulting high-fidelity signal and rich context enables security teams to prioritize, investigate and respond to threats in real-time.
Learn more at [Vectra Website](https://www.vectra.ai).

This pack is designed to quickly integrate with Vectra Detect platform to detect and analyze malicious attacks in progress by creating incident based on Accounts, Hosts or Detections. It gives security engineers visibility into advanced threats to speed detection and remediation response times.

<~XSIAM>This pack includes Cortex XSIAM content.</~XSIAM>

## What does this pack do?

- Create XSIAM events from detections and audits.
- Fetch accounts, hosts and detections from Vectra Detect.
- Bi-Directional Mirroring for accounts and hosts.
- List and Describe accounts, hosts, detections and users.
- List, Describe, Create and Resolve assignment for account and host.
- List, Describe and Create assignment outcomes.
- List, Create, Update and Delete notes for account, host and detection.
- List, Create and Remove tags for account, host and detection.
- List, Assign and Unassign members in group.
- Mark and Unmark detection as fixed.
- Mark all detections as fixed for account and host. 
- Get detection's PCAP file.
- Cleanup all incidents in XSOAR by closing duplicate incidents from Vectra Detect.

## Configuration on Server Side

To get up and running with this pack, you must have a valid API token on your Vectra AI instance. In your Vectra AI instance:

1. Navigate to **My Profile**.
2. Click the **General** tab.
3. Create an API Token.  

Be sure that the user has a role with sufficient permissions to do all the actions.

<~XSIAM>
## Collect Events from Vendor
### REST API

The integration uses the 2.2 API version of `detections` and `audits` endpoints to collect events.

</~XSIAM>