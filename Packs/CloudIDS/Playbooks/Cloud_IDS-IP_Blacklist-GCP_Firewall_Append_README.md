# Cloud IDS-IP Blacklist-GCP Firewall_Append
Use this playbook to update the ip list to patch the GCP firewall

## Playbook Inputs
---
GCPFirewallName - The Name of the GCP Firewall where the playbook should set the IPs

JsonObject - A JSON object containing the ip address to patch (from Extract)

## Playbook Outputs
---
GoogleCloudCompute.Operations error codes if applicable

## Playbook Image
---
![Cloud_IDS-IP_Blacklist-GCP_Firewall_Append](../doc_files/Cloud_IDS-IP_Blacklist-GCP_Firewall_Append.png)
