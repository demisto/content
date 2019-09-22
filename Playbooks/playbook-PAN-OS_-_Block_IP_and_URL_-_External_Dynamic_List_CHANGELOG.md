## [Unreleased]


## [19.9.1] - 2019-09-18
#### New Playbook
This playbook blocks IP addresses and URLs using Palo Alto Networks Panorama or Firewall External Dynamic Lists.
It checks if the EDL configuration is in place with the 'PAN-OS EDL Setup' sub-playbook (otherwise the list will be configured), and adds the input IPs and URLs to the relevant lists.