## [Unreleased]


## [19.11.1] - 2019-11-26
#### New Playbook
This playbook blocks Domains using Palo Alto Networks Panorama or Firewall External Dynamic Lists.
It checks if the EDL configuration is in place with the 'PAN-OS EDL Setup' sub-playbook
(otherwise the list will be configured), and adds the input Domains to the relevant lists.