## [Unreleased]


## [20.1.2] - 2020-01-22
#### New Playbook
Integrations list: Cortex (Traps, PAN-OS, Analytics)
This is a multipurpose playbook used for hunting and threat detection. The playbook receives inputs based on hashes, IP addresses, or domain names provided manually or from outputs by other playbooks. 
With the received indicators, the playbook leverages Palo Alto Cortex data received by products such as Traps, Analytics and Pan-OS to search for IP addresses and hosts related to that specific hash. 
The output provided by the playbook facilitates pivoting searches for possibly affected hosts, IP addresses, or users.