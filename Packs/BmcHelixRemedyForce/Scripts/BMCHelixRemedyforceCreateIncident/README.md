This script is used to simplify the process of creating the incident in BMC Helix Remedyforce. The script will consider the ID over the name of the argument when both are provided. Example: client_id is considered when both client_id and client_user_name are provided.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | bmcremedyforce  |
| Cortex XSOAR Version | 5.0.0 |

## Dependencies
---
This script uses the following commands and scripts.
* bmc-remedy-urgency-details-get
* bmc-remedy-status-details-get
* bmc-remedy-incident-create
* bmc-remedy-impact-details-get
* bmc-remedy-category-details-get
* bmc-remedy-template-details-get
* bmc-remedy-queue-details-get
* bmc-remedy-account-details-get
* bmc-remedy-broadcast-details-get
* bmc-remedy-service-offering-details-get
* bmc-remedy-user-details-get
* bmc-remedy-asset-details-get

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| client_user_name | User name of the client. Get the username using the 'bmc\-remedy\-user\-details\-get' command. |
| client_id | The unique ID of the client. It helps to select a client for a particular service request. Get the client ID from the email using the 'bmc\-remedy\-user\-details\-get' command. |
| category | Classifies the service request using standard classifications to track the reporting purposes. Get the category name using the 'bmc\-remedy\-category\-details\-get' command. |
| category_id | The unique ID of the category. Categories allow users to classify the incident or service request using standard classifications to track the reporting purposes. Get the category ID using the 'bmc\-remedy\-category\-details\-get' command. |
| queue | Name of the queue owner. Ghe queue name using the 'bmc\-remedy\-queue\-details\-get' command. |
| queue_id | The unique ID of the owner. Get the queue ID using the 'bmc\-remedy\-queue\-details\-get' command. |
| staff_user_name | The user name of the staff. Get the username using the 'bmc\-remedy\-user\-details\-get' command. |
| staff_id | The unique ID of the staff to whom the user wants to assign the record. Get the staff ID from the staff details using the 'bmc\-remedy\-user\-details\-get' command. |
| status | Displays the progress of the service request through its stages from opening to closure. Get the status name using the 'bmc\-remedy\-status\-details\-get' command. |
| status_id | The unique ID of the status that is used to display the progress of the service request through its stages from opening to closure. Get the status ID using the 'bmc\-remedy\-status\-details\-get' command. |
| urgency | Determines the priority of the service request. Get the urgency name using the 'bmc\-remedy\-urgency\-details\-get' command. |
| urgency_id | The unique ID of the urgency which is used to determine the priority of the service request. Get the urgency ID using the 'bmc\-remedy\-urgency\-details\-get' command. |
| template | Enable users to pre\-populate commonly used fields in a form. Get the template name using the 'bmc\-remedy\-template\-details\-get' command. |
| template_id | The unique ID of the template. Templates enable users to pre\-populate commonly used fields in a form. Get the template ID using the 'bmc\-remedy\-template\-details\-get' command. |
| description | The description of the incident that the user wants to create. |
| due_date | The date and time at which the incident should be completed. Use the yyyy\-MM\-ddTHH:mm:ss.SSS\+/\-HHmm or yyyy\-MM\-ddTHH:mm:ss.SSSZ formats to specify dateTime fields. |
| opened_date | The date and time at which the incident was created. Use the yyyy\-MM\-ddTHH:mm:ss.SSS\+/\-HHmm or yyyy\-MM\-ddTHH:mm:ss.SSSZ formats to specify dateTime fields. |
| impact | Determines the priority of the service request. Get the impact name using the 'bmc\-remedy\-impact\-details\-get' command. |
| impact_id | The unique ID of the impact which is used to determine the priority of the service request. Get the impact ID using the 'bmc\-remedy\-impact\-details\-get' command. |
| account | Name of the account. Get the account name using the 'bmc\-remedy\-account\-details\-get' command. |
| account_id | The account ID of the specific account. Get the account ID using the 'bmc\-remedy\-account\-details\-get' command. |
| broadcast | Enables users to send messages to the entire organization, selected groups within the organization and to external customers. Get the broadcast name using 'bmc\-remedy\-broadcast\-details\-get' command. |
| broadcast_id | The unique ID of the broadcast. Broadcast enables users to send messages to the entire organization, selected groups within the organization and to external customers. Get broadcast ID from the broadcast name using the 'bmc\-remedy\-broadcast\-details\-get' command. |
| service_offering | Link a service offering of an associated service. Get the service offering name using the 'bmc\-remedy\-service\-offering\-details\-get' command. |
| service_offering_id | The unique ID of the service offering. Get Users can get the service offering ID using the 'bmc\-remedy\-service\-offering\-details\-get' command. |
| asset | Name of the asset. Get the asset ID using the 'bmc\-remedy\-asset\-details\-get' command. |
| asset_id | The asset ID of the specific asset. Get the asset ID using the 'bmc\-remedy\-asset\-details\-get' command. |
| outage_start | The date and time when the service outage begins. Use the yyyy\-MM\-ddTHH:mm:ss.SSS\+/\-HHmm or yyyy\-MM\-ddTHH:mm:ss.SSSZ formats to specify dateTime fields. |
| outage_end | The date and time when the service outage ends. Use the yyyy\-MM\-ddTHH:mm:ss.SSS\+/\-HHmm or yyyy\-MM\-ddTHH:mm:ss.SSSZ formats to specify dateTime fields. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| BmcRemedyforce.Incident.Id | Incident Id. | String |
| BmcRemedyforce.Incident.Number | Incident number. | String |
| BmcRemedyforce.Incident.CreatedDate | Creation date &amp; time of Incident. | String |


## Script Example
```!BMCHelixRemedyforceCreateIncident client_id=0052w000004nuLjAAI using=BMCHelixRemedyforce_instance_jhanvi_acc```

## Context Example
```
{
    "BmcRemedyforce": {
        "Incident": {
            "CreatedDate": "2020-08-01 08:07:37",
            "Id": "a2U2w000000cRmqEAE",
            "Number": "00000153"
        }
    }
}
```

## Human Readable Output
The incident 00000153 is successfully created.
