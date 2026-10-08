To get an API client ID and secret, contact [CrowdStrike support](mailto:support@crowdstrike.com).


#### Important:

This integration is enabled by default for the new CrowdStrike Raptor version. <~XSOAR>Using older API versions is not supported.</~XSOAR>

### Required API client scopes

In order to use the CrowdStrike Falcon integration, the API client and secret must have the following scopes and permissions:

- Real Time Response - Read and Write
- Alerts - Read and Write
- IOC Manager - Read and Write
- IOA Exclusions - Read and Write
- Machine Learning Exclusions - Read and Write
- Detections - Read and Write
- Hosts - Read and Write
- Host Groups - Read and Write
- Spotlight Vulnerabilities - Read
- User Management - Read
- On-Demand Scans (ODS) - Read and Write
- Identity Protection Entities - Read and Write
- Identity Protection Detections - Read and Write
- Identity Protection Timeline - Read
- Identity Protection Assessment - Read
- Cases - Read and Write
- NGSIEM Search - Read and Write
- Recon - monitoring-rules Read and Write

### Troubleshooting

- When encountering connectivity or authorization errors, it is necessary to include the IP addresses corresponding to the relevant region in the CrowdStrike Falcon allow list. These IP addresses can be found in the [documentation on enabling access to Cortex](<~XSIAM> https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Resources-Required-to-Enable-Access </~XSIAM> <~XSOAR> https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Enable-access-to-Palo-Alto-Networks-resources </~XSOAR>) by searching for **Egress**.

- When encountering HTTP 429 response error code from CrowdStrike Falcon, use an engine as explained in this [link](<~XSIAM> https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Engines </~XSIAM> <~XSOAR> https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Engines </~XSOAR>).


<~XSOAR>

- When encountering missing incidents on the ***fetch-incidents*** command, make sure that the 'Fetch Type' integration parameter includes the type of the missing incidents.
Optional types are:
  - Endpoint Incident
  - Endpoint Detection
  - IDP Detection
  - Indicator of Misconfiguration
  - Indicator of Attack
  - Mobile Detection
  - On-Demand Scans Detection
  - OFP Detection
  - NGSIEM Detection
  - Third Party Detection
  - Recon notifications
  Records from the detection endpoint of the *CrowdStrike Falcon* UI could be of types: Endpoint Detection and OFP Detection.
</~XSOAR>

### Fetch Assets

- Integration supports **fetch-assets** option. CrowdStrike Falcon assets and vulnerabilities can be fetched and ingest into XSIAM Unified Asset Inventory.
Supported asset types include:
  - Spotlight
  - CNAPP Alerts
- Spotlight asset and vulnerability collection retrieves only vulnerabilities updated within the last 100 days, keeping each collection focused on recent data.

<~XSIAM>

#### Long running instance for Spotlight vulnerabilities

On large tenants a full Spotlight collection can take many hours - longer than the maximum execution time allowed for a single assets fetch. In such cases, the fetch is terminated before it completes. Enable the *Long running instance for Spotlight vulnerabilities* parameter (under the **Collect** section, **Advanced**) to run the Spotlight fetch in a long-running container instead, which is not bound by that execution time limit and lets a cycle run to completion. A new cycle starts every 24 hours, or immediately after the previous one ends if it ran longer.

When using this parameter, note that:

- **Only one collection mode per instance.** Do not enable *Fetch assets* on the same instance. Configure one instance for the long-running Spotlight fetch, and a separate instance for the regular assets fetch.
- **Spotlight vulnerabilities only.** The *Asset types to fetch* selection is ignored in this mode, and CNAPP Alerts are not collected. To collect CNAPP Alerts, use a separate instance with the regular assets fetch.

</~XSIAM>
