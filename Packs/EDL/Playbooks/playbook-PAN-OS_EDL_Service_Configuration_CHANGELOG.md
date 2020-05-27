## [Unreleased]


## [20.5.2] - 2020-05-26
#### New Playbook
This single-run playbook enables Cortex XSOAR built-in External Dynamic List (EDL) as a service for the system indicators, configures PAN-OS EDL Objects and the respective firewall policy rules.
The EDLs will continuously update for each indicator that matches the query syntax inputted in the playbook
(in order to validate to which indicators the query applied, you need to enter the query syntax from the indicator tab at the top of the playbook inputs window as well). 
If both the IP and URL indicator types exist in the query, it sorts the indicators into two EDLs, IP and URL. If only one indicator type exists in the query, only one EDL is created. 
The playbook then creates EDL objects directing to the indicator lists and firewall policy rules in PAN-OS. 
- It is recommended to configure a dedicated EDL Service instance for the usage of this playbook.
- In case it is needed to edit or update the EDL query after this playbook run, use the panorama-edit-edl command and panorama integration to update the URL containing the indicator query syntax.