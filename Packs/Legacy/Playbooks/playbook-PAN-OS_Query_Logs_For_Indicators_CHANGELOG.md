## [Unreleased]


## [19.12.0] - 2019-12-10


## [19.12.1] - 2019-12-01
#### New Playbook
Use this playbook to query PANW PAN-OS for indicators. The playbook searches in each of the five log types according to the inputted indicators to search, such as ip addresses, urls/domains, file hashes (sha256).

This playbook implements generic polling as an array for all submitted queries.
The playbook has the following structure.

1. Receive indicators as inputs.
2. Check which indicators were inputted and create queries for the relevant log types.
3. (optional) Run polling to get the submitted query results.