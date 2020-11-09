This playbook remediates Prisma Cloud GCP Kubernetes Engine alerts.  It calls sub-playbooks that perform the actual remediation steps.

Remediation:
* GCP Kubernetes Engine Clusters Basic Authentication is set to Enabled
* GCP Kubernetes Engine Clusters have HTTP load balancing disabled
* GCP Kubernetes Engine Clusters have Legacy Authorization enabled
* GCP Kubernetes Engine Clusters have Master authorized networks disabled
* GCP Kubernetes Engine Clusters have Network policy disabled
* GCP Kubernetes Engine Clusters have Stackdriver Logging disabled
* GCP Kubernetes Engine Clusters have Stackdriver Monitoring disabled
* GCP Kubernetes Engine Clusters have binary authorization disabled
* GCP Kubernetes Engine Clusters web UI/Dashboard is set to Enabled
* GCP Kubernetes cluster intra-node visibility disabled


## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* Prisma Cloud Remediation - GCP Kubernetes Engine Cluster Misconfiguration

### Integrations
* RedLock

### Scripts
This playbook does not use any scripts.

### Commands
* closeInvestigation
* redlock-dismiss-alerts

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| AutoRemediateKubernetesEngine | Execute GCP Kubernetes Engine remediation automatically? | no | Optional |
| policyId | Grab the Prima Cloud policy Id. | incident.labels.policy | Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Prisma Cloud Remediation - GCP Kubernetes Engine Misconfiguration](https://github.com/demisto/content/raw/master/Packs/PrismaCloud/doc_files/PCR_-_GCP_Kub_Engine_Misconfig.png)
