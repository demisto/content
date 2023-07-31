# Cloud Incident Response

As enterprise resources are moving to the cloud, attackers develop dedicated attacks to be able to access, manipulate, and exfiltrate cloud information and resources. Adequate response and remediation of such attacks requires cloud knowledge and extensive context.

This content pack helps you automate collection from cloud logs and then perform investigation and automated remediation of incidents based on cloud infrastructure activities in AWS, Azure, and GCP. It does not require an agent, resulting in a shorter time to resolution for cloud incidents.

To analyze cloud infrastructure alerts, a XSIAM license or a Cortex XDR Pro per TB license is required. Audit logs from the cloud provider should be ingested. The configuration varies between the different cloud providers:

[Set up cloud audit logs for Azure](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Ingest-Logs-from-Google-Kubernetes-Engine)  
[Set up cloud audit logs for AWS](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/External-Data-Ingestion-Vendor-Support)  
[Set up cloud audit logs for GCP](https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-Pro-Administrator-Guide/Ingest-Logs-and-Data-from-a-GCP-Pub/Sub?tocId=xlX52RIi48J7B4I5mEr4mw)

## What does this pack do?

This pack includes a collection of investigation and response playbooks for cloud alerts, aiding analyst investigations. The playbooks can also be used as templates to enrich, hunt, and block indicators.

The playbooks included in this pack help save time and automate repetitive tasks:

- Extract and enrich all relevant indicators from the alert.
- Automate alert triage.
- Investigate and hunt for additional activities by running advanced queries across major CSPs.
- Interact with the analyst to choose a remediation path or close the incident as a false positive based on the gathered information and incident severity.
- Hunt for related IOCs.
- Remediate the alerts by blocking malicious indicators, terminating newly created resources, and more.

As part of this pack, you will also get an out-of-the-box layout to facilitate analyst investigation. All of these components are easily customizable to suit the needs of your organization.

For XSIAM, the playbooks are also included in the "Playbook Recommendation".

## Supported Use Cases

### Cortex XSIAM Playbooks

[Cloud Token Theft](https://xsoar.pan.dev/docs/reference/playbooks/cloud-token-theft-response)

[Cloud Cryptojacking](https://xsoar.pan.dev/docs/reference/playbooks/x-cloud-cryptomining)

### Cortex XSOAR Playbooks

[Cortex XDR - Cloud Token Theft](https://xsoar.pan.dev/docs/reference/playbooks/cortex-xdr---x-cloud-token-theft-response)

[Cortex XDR - Cloud Cryptojacking](https://xsoar.pan.dev/docs/reference/playbooks/cortex-xdr---cloud-cryptomining)

### Investigative Playbooks

[Cloud Threat Hunting - Persistence](https://xsoar.pan.dev/docs/reference/playbooks/cloud-threat-hunting---persistence)

![Cloud Incident Response](doc_files/Cloud_Incident_Response.png)