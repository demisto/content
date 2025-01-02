To get an API client ID and secret, contact [CrowdStrike support](mailto:support@crowdstrike.com).


#### Important:

This integration is enabled by default for the new CrowdStrike Raptor version. For the older API version (pre-Raptor release), check the "Use legacy API" checkbox<~XSOAR> and select the Legacy mapper as well</~XSOAR>.

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
- Incidents - Read and Write
- Spotlight Vulnerabilities - Read
- User Management - Read
- On-Demand Scans (ODS) - Read and Write
- Identity Protection Entities - Read and Write
- Identity Protection Detections - Read and Write
- Identity Protection Timeline - Read
- Identity Protection Assessment - Read

<~XSIAM>

### Troubleshooting

- When encountering connectivity or authorization errors in Cortex XSIAM, it is necessary to include the IP addresses corresponding to the relevant region in the CrowdStrike Falcon allow list. These IP addresses can be found in the [documentation on enabling access to Cortex XSIAM](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Resources-Required-to-Enable-Access) under the **Egress** section.

- When encountering HTTP 429 response error code from CrowdStrike Falcon in Cortex XSIAM, use an engine as explained in this [link](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Administrator-Guide/Engines).
</~XSIAM>

<~XSOAR_SAAS>

### Troubleshooting

- When encountering connectivity or authorization errors in Cortex XSOAR 8, it is necessary to include the IP addresses corresponding to the relevant region in the CrowdStrike Falcon allow list. These IP addresses can be found in the [documentation on enabling access to Cortex XSOAR](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Administrator-Guide/Enable-Access-to-Cortex-XSOAR) under the **Egress** section.

- When encountering HTTP 429 response error code from CrowdStrike Falcon in Cortex XSOAR 8, use an engine as explained in this [link](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Administrator-Guide/Engines).
</~XSOAR_SAAS>
