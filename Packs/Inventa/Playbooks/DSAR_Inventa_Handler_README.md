#Usage
Use this playbook to create or use existing Inventa ticket in order to obtain information on the PII entities for 
the Data Subject as well as file or database storages which contain information about the Data Subject.

####Triggers
The Inventa's DSAR engine will report all the PII categories and info storages containing information about Data Subject.
This playbook is automatically triggered by the Incident creation and is used for enrichment of the Incident information

####Configuration
No extra configuration required. However, in case of disruptions or connectivity issues some tasks, involving 
Inventa's API call may fail and will require to be manually restarted.

####Best practices and suggestions
It's highly recommended to use existing ticket's ID if the Inventa DSAR Engine already contains relevant DSAR request. 
That will allow to minimize duplicate tickets within Inventa.

#Dependencies
* Builtin

##Sub-playbooks
This playbook does not use sub-playbooks.

##Integrations
This playbook is designed to be used in Inventa integration.

##Scripts
* Set
* SearchIncidentsV2
* linkIncidents
* SetGridField

#Playbook inputs
| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- | 
| National ID | National ID of a Data Subject. Used as a part of a constraint. | - | Optional |
| Passport Number | Passport Number of a Data Subject. Used as a part of a constraint. | - | Optional |
| Driver License | Driver License of a Data Subject. Used as a part of a constraint. | - | Optional |
| Tax ID | Tax ID of a Data Subject. Used as a part of a constraint. | - | Optional |
| Credit Card Number | Credit Card Number of a Data Subject. Used as a part of a constraint. | - | Optional |
| First Name | First Name of a Data Subject. Used as a part of a constraint. | - | Optional |
| Surname | Surname of a Data Subject. Used as a part of a constraint. | - | Optional |
| Full Name | Full Name of a Data Subject. Used as a part of a constraint. | - | Optional |
| Vehicle Number | Vehicle Number of a Data Subject. Used as a part of a constraint. | - | Optional |
| Phone Number | Phone Number of a Data Subject. Used as a part of a constraint. | - | Optional |
| Birthday | Birthday of a Data Subject. Used as a part of a constraint. | - | Optional |
| City | City of a Data Subject. Used as a part of a constraint. | - | Optional |
| Street Address | Street Address of a Data Subject. Used as a part of a constraint. | - | Optional |
| Reason | Reason of a Data Subject. Required by Inventa DSAR Engine for creating a ticket. | - | Required |
| Ticket | Ticket of a Data Subject. Used to obtain all relevant information on the ticket and data stored in it from Inventa. | - | Optional |

#Playbook outputs
There are no outputs for this playbook.

#Playbook Image