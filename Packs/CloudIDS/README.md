# CloudIDS
Google Cloud IDS, a next-generation advanced intrusion detection service that provides threat detection for intrusions, malware, spyware and command-and-control attacks.


## What does this packs do?
### Playbook
* `IP Blacklist - GCP Firewall`: Gets the attacker's IP address from
  Cloud IDS through Google Pub/Sub. Then, `IP Blacklist - GCP Firewall` will update the ip list to patch GCP
  firewall.
  
#### Flow Chart of Playbook 
* [IP Blacklist - GCP Firewall](Playbooks/IPBlacklistGCPFirewall_README.md)

![flow chart](Playbooks/IPBlacklistGCPFirewall.png)

## Dependencies
### Packs
* [GoogleCloudCompute](../GoogleCloudCompute).


