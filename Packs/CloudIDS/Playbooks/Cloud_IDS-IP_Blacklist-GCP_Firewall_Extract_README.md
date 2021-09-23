# Cloud IDS-IP Blacklist-GCP Firewall_Extract
Use this playbook to extract an attacker's IP address from Cloud IDS through Google Pub/Sub, then update the ip list to patch GCP firewall.

## Playbook Inputs
---
GCPFirewallName - The Name of the GCP Firewall where the playbook should set the IPs

## Playbook Outputs
---
JsonObject - A JSON object loaded with the attacker's IP address.

## Playbook Image
---
![Cloud_IDS-IP_Blacklist-GCP_Firewall_Extract](../doc_files/Cloud_IDS-IP_Blacklist-GCP_Firewall_Extract.png)
