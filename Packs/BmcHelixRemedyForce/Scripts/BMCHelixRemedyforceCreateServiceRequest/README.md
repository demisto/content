This script is used to simplify the process of creating a service request in BMC Helix Remedyforce. The script will consider ID over the name of the argument when both are provided. Example: client_id is considered when both client_id and client_user_name are provided.
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
* bmc-remedy-category-details-get
* bmc-remedy-account-details-get
* bmc-remedy-user-details-get
* bmc-remedy-service-request-create
* bmc-remedy-service-request-definition-get
* bmc-remedy-urgency-details-get
* bmc-remedy-status-details-get
* bmc-remedy-queue-details-get
* bmc-remedy-impact-details-get

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| client_user_name | User name of the client. Get the username using the 'bmc\-remedy\-user\-details\-get' command. |
| client_id | The unique ID of the client. It helps to select a client for a particular service request. Get the client ID from the email using the 'bmc\-remedy\-user\-details\-get' command. |
| category | Classifies the service request using standard classifications to track the reporting purposes. Get the category name using the 'bmc\-remedy\-category\-details\-get' command. |
| category_id | The unique ID of the category. Categories allow users to classify the incident or service request using standard classifications to track the reporting purposes. Get the category ID using the 'bmc\-remedy\-category\-details\-get' command. |
| queue | Name of the queue owner. Get the queue name using the 'bmc\-remedy\-queue\-details\-get' command. |
| queue_id | The unique ID of the queue owner. Get the queue ID using the 'bmc\-remedy\-queue\-details\-get' command. |
| staff_user_name | The user name of the staff. Get the username using the 'bmc\-remedy\-user\-details\-get' command. |
| staff_id | The unique ID of the staff to whom the user wants to assign the record. Get the staff ID from the staff details using the 'bmc\-remedy\-user\-details\-get' command. |
| status | Displays the progress of the service request through its stages from opening to closure. Get the status name using the 'bmc\-remedy\-status\-details\-get' command. |
| status_id | The unique ID of the status that is used to display the progress of the service request through its stages from opening to closure. Users can get the status ID  using the'bmc\-remedy\-status\-details\-get' command. |
| urgency | Determines the priority of the service request. Get the urgency name using the 'bmc\-remedy\-urgency\-details\-get' command. |
| urgency_id | The unique ID of the urgency which is used to determine the priority of the service request. Get the urgency ID using the 'bmc\-remedy\-urgency\-details\-get' command. |
| service_request_definition | The Service Request Definition Name. Get the Service Request Definition name using the 'bmc\-remedy\-service\-request\-definition\-get' command. |
| service_request_definition_id | The unique ID of the Service Request Definition. Get the Service Request Definition ID using the 'bmc\-remedy\-service\-request\-definition\-get' command. |
| service_request_definition_params | Each service request definition expects specific parameters to be supplied. Specify the parameters as a delimiter \(;\) separated string. Example: 'param1=value1; param2=value2'. |
| impact | Determine the priority of the service request. Users can get the impact name using the 'bmc\-remedy\-impact\-details\-get' command. |
| impact_id | The unique ID of the impact which is used to determine the priority of the service request. Get the impact ID using the 'bmc\-remedy\-impact\-details\-get' command. |
| account | Name of the account. Get the account name using the 'bmc\-remedy\-account\-details\-get' command. |
| account_id | The account ID of the specific account. Get the account ID using the 'bmc\-remedy\-account\-details\-get' command. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| BmcRemedyforce.ServiceRequest.Number | Service request number. | String |
| BmcRemedyforce.ServiceRequest.Id | Service request Id. | String |
| BmcRemedyforce.ServiceRequest.CreatedDate | Creation date &amp; time of service request. | String |


## Script Example
```!BMCHelixRemedyforceCreateServiceRequest service_request_definition_id="a3H2w000000TfAPEA0" using="BMCHelixRemedyforce_instance_jhanvi_acc"```

## Context Example
```
{
    "BmcRemedyforce": {
        "ServiceRequest": {
            "CreatedDate": "2020-08-01T08:08:16Z",
            "Id": "a2U2w000000cRmvEAE",
            "Number": "00000154"
        }
    }
}
```

## Human Readable Output
The service request 00000154 is successfully created.
