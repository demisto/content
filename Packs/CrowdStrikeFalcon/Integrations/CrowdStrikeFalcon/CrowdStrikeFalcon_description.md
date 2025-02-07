To get an The API client ID and secret, contact the crowdstrike support: support@crowdstrike.com


#### Important:
This integration is enabled by default for the new CrowdStrike Raptor version. For the older API version (pre-Raptor release), ensure you check the "Use legacy API" checkbox and select the Legacy mapper as well.

### Required API client scope
In order to use the CrowdStrike Falcon integration, your API client must be provisioned with the following scope and permissions:

- Real Time Response - Read and Write
- Alerts - Read and Write
- IOC Manager - Read and Write
- IOA Exclusions - Read and Write
- Machine Learning Exclusions - Read and Write
- Detections - Read and Write
- Hosts - Read and Write
- Host Groups - Read and Write
- Incidents - Read and Write
- Spotlight Vulnerabilities - Read
- User Management - Read
- On-Demand Scans (ODS) - Read and Write
- Identity Protection Entities - Read and Write
- Identity Protection Detections - Read and Write
- Identity Protection Timeline - Read
- Identity Protection Assessment - Read


### Troubleshooting
* When encountering connectivity or authorization errors within Cortex XSOAR 8, it is necessary to include the IP addresses corresponding to the relevant region in the CrowdStrike Falcon allow list. These IP addresses can be found in [this](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Administrator-Guide/Enable-Access-to-Cortex-XSOAR) 
documentation, under **Egress - Used for communication between Cortex XSOAR and customer resources**.
* When encountering a 429 error code returned from Crowdstrike Falcon within Cortex XSOAR 8, the solution is to use an engine as explained in this [link](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Administrator-Guide/Engines).
* When encountering missing incidents on the ***fetch-incidents*** command, make sure that the 'Fetch Type' integration parameter includes the type of the missing incidents.
Optional types are:
  - Endpoint Incident
  - Endpoint Detection
  - IDP Detection
  - Indicator of Misconfiguration
  - Indicator of Attack
  - Mobile Detection
  - On-Demand Scans Detection
  - OFP Detection
  Records from the detection endpoint of the *CrowdStrike Falcon* UI could be of types: Endpoint Detection and OFP Detection.