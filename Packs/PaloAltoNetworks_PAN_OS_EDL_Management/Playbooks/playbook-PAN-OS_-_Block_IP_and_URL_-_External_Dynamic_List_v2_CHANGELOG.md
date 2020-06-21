## [Unreleased]
-

## [20.5.0] - 2020-05-12
#### New Playbook
This playbook blocks IP addresses and URLs using Palo Alto Networks Panorama or Firewall External Dynamic Lists.
It checks if the EDL configuration is in place with the 'PAN-OS EDL Setup' sub-playbook (otherwise the list will be configured), and adds the inputted IPs and URLs to the relevant lists.