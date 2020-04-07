## [Unreleased]


## [20.1.2] - 2020-01-22
#### New Playbook
This playbook will pull Panorama queried threat logs and check for any correlating assets that are found to have a minimum of high level vulnerabilities. If so, it will block the the IP using Panorama's PAN-OS - Block IP and URL - External Dynamic List playbook.