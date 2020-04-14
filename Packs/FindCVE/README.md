## Overview
---

Many times, secuity teams would like to know whether there is a coverage for a particular CVE or a list of CVEs, based on a threat report, or a security audit.
`FindCVE` parse through the pre-defined signatures, map the CVE to the corresponding circle.lu decription, as well as map out: 
1. CVE 
2. Threat Name
3. CVE link from circle.lu
4. Severity
5. ThreatID
6. Default action
## `FindCVE` Playbook
Playbook 1: NetOps Panorama coverage by CVE. The starting point is a list of CVEs (one or more), which the user will enter when creating the appropriate incident type. The playbook will use a panorama command to retrieve all the pre-defined signatures, and an automation script to map the proper CVEs from the input to the corresponding found within panorama command. The next step is to correlate each found CVEs with the circle.lu description and expose additional fields to for the output to the user.
## `Panorama CVE Coverage` Automation script
This script handles the user input and data retrieved from the pre-defined signatures. The script will correlate the CVE to the circle.lu and build the output to the user.

## Panorama Command
`panorama-get-predefined-threats-list` This command will retrieve ALL pre-defined signatures. The list is over 10000 entries. Therefore, the demisto server will save the results into a file


## Use Cases
1. A new threat report is coming out to the field, and either a customer or an SE would like to know whether Palo Alto Networks provides coverage for the CVEs listed in the report.
2. Performing a threat audit and looking for particular coverage availability for a list of CVEs.
3. Providing a reply for a tender that is requiring coverage for a list of CVE.


## Configure FindCVE on Demisto
---

1. Navigate to __Incidents__ > __New Incident__ to create a new incident.
2. For the __Inciden Type__ use the dropdown menue and choose `__Panorama Threat Coverage__`
3. After creating your incident, navigate to the __CVE List__ tab of your incident.
4. Enter the list of CVEs in the __CVE_List__ field
5. Enter the serial number of the firewall you want to check in the __Target__ filed. Leafing the __Taeget__ field empty, the playbook will run on the __Panorama__ instance.
