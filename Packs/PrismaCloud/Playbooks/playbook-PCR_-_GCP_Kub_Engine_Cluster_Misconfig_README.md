This playbook remediates the following Prisma Cloud GCP Kubernetes Engine Cluster alerts.

Prisma Cloud policies remediated:

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
This playbook does not use any sub-playbooks.

### Integrations
* GoogleKubernetesEngine

### Scripts
This playbook does not use any scripts.

### Commands
* gcloud-clusters-set-muster-auth
* gcloud-clusters-describe
* gcloud-clusters-set-binary-auth
* gcloud-clusters-set-intra-node-visibility
* gcloud-clusters-set-legacy-auth
* gcloud-clusters-set-master-authorized-network
* gcloud-clusters-set-k8s-stackdriver
* gcloud-clusters-set-addons

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| policyId | Prisma Cloud policy Id. |  | Required |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Prisma Cloud Remediation - GCP Kubernetes Engine Cluster Misconfiguration](https://github.com/demisto/content/raw/master/Packs/PrismaCloud/doc_files/PCR_-_GCP_Kub_Engine_Cluster_Misconfig.png)
