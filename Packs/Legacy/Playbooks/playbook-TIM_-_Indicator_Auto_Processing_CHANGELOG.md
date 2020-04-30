## [Unreleased]


## [20.4.1] - 2020-04-29
Added new subplaybook, TIM - Process CIDR Indicators By Size.


## [20.3.4] - 2020-03-30
#### New Playbook
This playbook uses several sub playbooks to process and tag indicators, which is used to identify indicators that shouldn't be blacklisted. For example IP indicators that belong to business partners or important hashes we wish to not process. Additional sub playbooks can be added for improving the business logic and tagging according to the user's needs. This playbook doesn't have its own indicator query as it processes indicators provided by the parent playbook query. To enable the playbook, provide the relevant list names in the sub playbook indicators, such as the ApprovedHashList, OrganizationsExternalIPListName, BusinessPartnersIPListName, etc. Also be sure to append the results of additional sub playbooks to Set indicators to Process Indicators for the additional playbooks results to be in the outputs.