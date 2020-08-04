This script is used to simplify the process of creating a service request in BMC Helix Remedyforce. Script will consider ID over the name of the argument when both are provided. Example: client_id is considered when both client_id and client_user_name are provided.
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
| service_request_definition | Service Request Definition Name. Users can get the service request definition name using 'bmc\-remedy\-service\-request\-definition\-get' command. |
| service_request_definition_id | The unique id of the service request definition. Users can get the service request definition id from service request definition name using 'bmc\-remedy\-service\-request\-definition\-get' command. |
| service_request_definition_params | Each service request definition expects specific parameters to be supplied. Specify the parameters as a delimiter \(;\) separated string. Example: 'param1=value1; param2=value2'. |
| impact | Impact is used to determine the priority of the service request. Users can get the urgency name using 'bmc\-remedy\-impact\-details\-get' command. |
| impact_id | impact\_id is the unique id of the impact which is used to determine the priority of the service request. Users can get the impact id from the impact name using 'bmc\-remedy\-impact\-details\-get' command. |
| account | Name of the account. Users can get the account name using 'bmc\-remedy\-account\-details\-get' command. |
| account_id | account\_id of the specific account. Users can get the account id from the account name using 'bmc\-remedy\-account\-details\-get' command. |

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
