This script is used to simplify the process of creating the incident in BMC Helix Remedyforce. Script will consider ID over the name of the argument when both are provided. Example: client_id is considered when both client_id and client_user_name are provided.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | bmcremedyforce  |
| Demisto Version | 5.0.0 |

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
| client_user_name | User name of the client. Users can get the username using 'bmc\-remedy\-user\-details\-get' command. |
| client_id | client\_id is the unique id of the client. It helps to select a client for a particular service request. Users can get the client id from the email using 'bmc\-remedy\-user\-details\-get' command. |
| category | Categories allow users to classify the service request using standard classifications to track the reporting purposes. Users can get the category name using 'bmc\-remedy\-category\-details\-get' command. |
| category_id | category\_id is the unique id of the category. Categories allow users to classify the incident or service request using standard classifications to track the reporting purposes. Users can get the category id from the category name using 'bmc\-remedy\-category\-details\-get' command. |
| queue | Name of the queue as owner. Users can get the queue name using 'bmc\-remedy\-queue\-details\-get' command. |
| queue_id | queue\_id is the unique id of the owner. Users can get the queue id from the owner name using 'bmc\-remedy\-queue\-details\-get' command. |
| staff_user_name | User name of the staff. Users can get the username using 'bmc\-remedy\-user\-details\-get' command. |
| staff_id | staff\_id is the unique id of the staff to whom the user wants to assign the record. Users can get the staff id from the staff details using 'bmc\-remedy\-user\-details\-get' command. |
| status | Status is used to display the progress of the service request through its stages of opening to closure. Users can get the status name using 'bmc\-remedy\-status\-details\-get' command. |
| status_id | status\_id is the unique id of the status that is used to display the progress of the service request through its stages of opening to closure. Users can get the status id from the status name using 'bmc\-remedy\-status\-details\-get' command. |
| urgency | Urgency is used to determine the priority of the service request. Users can get the urgency name using 'bmc\-remedy\-urgency\-details\-get' command. |
| urgency_id | urgency\_id is the unique id of the urgency which is used to determine the priority of the service request. Users can get the urgency id from the urgency name using 'bmc\-remedy\-urgency\-details\-get' command. |
| template | Templates enable users to pre\-populate commonly used fields in a form. Users can get the template name using 'bmc\-remedy\-template\-details\-get' command. |
| template_id | template\_id is the unique id of the template. Templates enable users to pre\-populate commonly used fields in a form. Users can get the template id from the template name using 'bmc\-remedy\-template\-details\-get' command. |
| description | This field represents the description of the incident that the user wants to create. |
| due_date | due\_date is the date and time at which the incident should be completed. Use the yyyy\-MM\-ddTHH:mm:ss.SSS\+/\-HHmm or yyyy\-MM\-ddTHH:mm:ss.SSSZ formats to specify dateTime fields. |
| opened_date | opened\_date is the date and time at which the incident was created. Use the yyyy\-MM\-ddTHH:mm:ss.SSS\+/\-HHmm or yyyy\-MM\-ddTHH:mm:ss.SSSZ formats to specify dateTime fields. |
| impact | Impact is used to determine the priority of the service request. Users can get the impact name using 'bmc\-remedy\-impact\-details\-get' command. |
| impact_id | impact\_id is the unique id of the impact which is used to determine the priority of the service request. Users can get the impact id from the impact name using 'bmc\-remedy\-impact\-details\-get' command. |
| account | Name of the account. Users can get the account name using 'bmc\-remedy\-account\-details\-get' command. |
| account_id | account\_id of the specific account. Users can get the account id from the account name using 'bmc\-remedy\-account\-details\-get' command. |
| broadcast | Broadcast enables users to send messages to the entire organization, selected groups within the organization and to external customers. Users can get the broadcast name using 'bmc\-remedy\-broadcast\-details\-get' command. |
| broadcast_id | broadcast\_id is the unique id of the broadcast. Broadcast enables users to send messages to the entire organization, selected groups within the organization and to external customers. Users can get the broadcast id from the broadcast name using 'bmc\-remedy\-broadcast\-details\-get' command. |
| service_offering | Link a service offering of an associated service. Users can get the service\_offering name using 'bmc\-remedy\-service\-offering\-details\-get' command. |
| service_offering_id | service\_offering\_id is the unique id of the service\_offering. Users can get the service\_offering\_id from the service\_offering name using 'bmc\-remedy\-service\-offering\-details\-get' command. |
| asset | Name of the asset. Users can get the asset id from the asset name using 'bmc\-remedy\-asset\-details\-get' command. |
| asset_id | asset\_id of the specific asset. Users can get the asset id from the asset name using 'bmc\-remedy\-asset\-details\-get' command. |
| outage_start | outage\_start is the date and time when the service outage begins. Use the yyyy\-MM\-ddTHH:mm:ss.SSS\+/\-HHmm or yyyy\-MM\-ddTHH:mm:ss.SSSZ formats to specify dateTime fields. |
| outage_end | outage\_end is the date and time when the service outage ends. Use the yyyy\-MM\-ddTHH:mm:ss.SSS\+/\-HHmm or yyyy\-MM\-ddTHH:mm:ss.SSSZ formats to specify dateTime fields. |

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
