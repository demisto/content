# Cloud IDS-IP Blacklist-GCP Firewall_Combine
Use this playbook to extract an attacker's IP address from Cloud IDS through Google Pub/Sub, then update the ip list to patch GCP firewall.

This playbook calls both Extract and Append.

## Playbook Inputs
---
GCPFirewallName - The Name of the GCP Firewall where the playbook should set the IPs

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![Cloud_IDS-IP_Blacklist-GCP_Firewall_Combine](../doc_files/Cloud_IDS-IP_Blacklist-GCP_Firewall_Combine.png)
