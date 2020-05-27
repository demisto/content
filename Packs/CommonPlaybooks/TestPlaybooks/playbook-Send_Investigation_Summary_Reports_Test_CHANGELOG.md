## [Unreleased]


## [20.5.2] - 2020-05-26
#### New Playbook
Playbook should be run as a scheduled job at a recommended interval of once every 15 minutes. Playbook simply calls sub playbook: "Send Investigation Summary Reports" and closes the incident. Playbook by default will search all closed incidents within the last hour. If you wish to run the playbook more frequently, you should adjust the search query of the child playbook: Send Investigation Summary Reports.