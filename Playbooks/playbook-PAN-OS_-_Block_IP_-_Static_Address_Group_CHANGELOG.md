## [Unreleased]


## [19.9.1] - 2019-09-18
#### New Playbook
This playbook blocks IP addresses using Static Address Groups in Palo Alto Networks Panorama or Firewall.
The playbook receives malicious IP addresses and an address group name as inputs, verifies that the addresses are not already a part of the address group, adds them and commits the configuration.

***Note - The playbook does not block the address group communication using a policy block rule. This step will be taken once outside of the playbook.