# CloudIDS
Google Cloud IDS is a next-generation advanced intrusion detection service that provides threat detection for intrusions, malware, spyware, and command-and-control attacks.

## What does this pack do?

### Playbook
* `Cloud_IDS-IP_Blacklist-GCP_Firewall_Extract`: Gets the attacker's IP address from Cloud IDS through Google Pub/Sub. 
  `Cloud_IDS-IP_Blacklist-GCP_Firewall_Append` will update the ip list so GCP automatically blocks the IP address.
  
#### Flow Chart of Playbook 
* [Cloud_IDS-IP_Blacklist-GCP_Firewall](https://github.com/demisto/content/blob/423e13b69b375288d3ec2183bfbd4d2ee6fe018c/Packs/CloudIDS/Playbooks/Cloud_IDS-IP_Blacklist-GCP_Firewall_README.md)
![Playbook Image](doc_files/Cloud_IDS-IP_Blacklist-GCP_Firewall_Combine.png)
![Playbook Image](doc_files/Cloud_IDS-IP_Blacklist-GCP_Firewall_Extract.png)
![Playbook Image](doc_files/Cloud_IDS-IP_Blacklist-GCP_Firewall_Append.png)


