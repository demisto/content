## [Unreleased]


## [19.10.0] - 2019-10-03
#### New Playbook
This playbook is used for querying the PANW threat intelligence Autofocus system. The playbook accepts indicators such as IP's, hashes, domains to run basic queries or mode advanced queries that can leverage several query parameters. In order to run the more advanced queries its recommended to use the Autofocus UI https://autofocus.paloaltonetworks.com/#/dashboard/organization to created a query and than use the export search button. The result can be used as a playbook input.

The playbook supports searching both the Samples API and the sessions API.