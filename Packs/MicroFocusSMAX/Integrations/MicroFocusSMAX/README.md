Fetch SMAX incidents, requests and automate different SMAX case management actions
This integration was integrated and tested with version 2021.08 of MicroFocus SMAX

## Configure MicroFocus SMAX in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Object To Fetch |  | False |
| Your SMAX Management URL |  | True |
| Tenant ID | The tenant ID is the number following TENANTID= in your management URL | False |
| Username | The admin credentials used to integration with SMAX | True |
| Password |  | True |
| Fetch Filter | Fetch filter , example:  Status = 'Ready'" for Incident queries, see "REST API collection query protocol" in SMAX documentation to know how to use the filter | False |
| Fields To Fetch | Fields to return, for example: "Priority,Category" for an entity of type "Incident | False |
| Fetch Limit | The maximum number of incidents to fetch per fetch command | False |
| Fetch Start | Fetch start in days | False |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |

## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### microfocus-smax-get-entity
***
Get any entity details


#### Base Command

`microfocus-smax-get-entity`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_type | Entity type, for example: "Incident", the type is case-sensitive. Possible values are: . | Required | 
| entity_id | Entity Id . | Required | 
| entity_fields | Fields to return, for example: "Priority,Category" for an entity of type "Incident". | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicroFocus.SMAX.Entities.properties.Id | String | Entity Id | 
| MicroFocus.SMAX.Entities.properties.Name | String | Entity name | 


#### Command Example
```!microfocus-smax-get-entity entity_type="Incident" entity_id="16989" entity_fields="Description,Urgency,Status,RegisteredForActualService"```

#### Context Example
```json
{
    "MicroFocus": {
        "SMAX": {
            "Entities": {
                "entity_type": "Incident",
                "properties": {
                    "Description": "Test Description",
                    "DisplayLabel": "test66122",
                    "Id": "16989",
                    "LastUpdateTime": 1635339214960,
                    "RegisteredForActualService": "11639",
                    "Status": "Ready",
                    "Urgency": "SlightDisruption"
                },
                "related_properties": {}
            }
        }
    }
}
```

#### Human Readable Output

>### Entity Details:
>|Description|DisplayLabel|Id|LastUpdateTime|RegisteredForActualService|Status|Type|Urgency|
>|---|---|---|---|---|---|---|---|
>| Test Description | test66122 | 16989 | 1635339214960 | 11639 | Ready | Incident | SlightDisruption |


### microfocus-smax-query-entities
***
Query entities' details using a collection query filter


#### Base Command

`microfocus-smax-query-entities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entity_type | Entity type, for example: "Incident", the type is case-sensitive. | Required | 
| query_filter | Query filter , example:  Status = 'Ready'" for Incident queries, see "REST API collection query protocol" in SMAX documentation to know how to use the filter. | Optional | 
| entity_fields | Fields to return, for example: "Priority,Category" for an entity of type "Incident". | Optional | 
| order_by | The order query parameter specifies the order in which the returned resources are placed, example: "Id desc". | Optional | 
| size | Specify the maximum number of resources requested to be returned. | Optional | 
| skip | Specify how many resources should be skipped by specifying the starting index of the returned result. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicroFocus.SMAX.Entities.properties.Id | String | Entity Id | 
| MicroFocus.SMAX.Entities.properties.Name | String | Entity name | 
| MicroFocus.SMAX.Query.query_time | String | Query time | 
| MicroFocus.SMAX.Query.total_count | String | Query results total count | 
| MicroFocus.SMAX.Query.completion_status | String | Query result status | 


#### Command Example
```!microfocus-smax-query-entities entity_type="Incident" query_filter="Status = 'Ready'" entity_fields="Status,Urgency" order_by="Id desc" size="5"```

#### Context Example
```json
{
    "MicroFocus": {
        "SMAX": {
            "Entities": [
                {
                    "entity_type": "Incident",
                    "properties": {
                        "Id": "17658",
                        "LastUpdateTime": 1635338444483,
                        "Status": "Ready",
                        "Urgency": "NoDisruption"
                    },
                    "related_properties": {}
                },
                {
                    "entity_type": "Incident",
                    "properties": {
                        "Id": "17656",
                        "LastUpdateTime": 1635331698499,
                        "Status": "Ready",
                        "Urgency": "SlightDisruption"
                    },
                    "related_properties": {}
                },
                {
                    "entity_type": "Incident",
                    "properties": {
                        "Id": "17652",
                        "LastUpdateTime": 1635256251981,
                        "Status": "Ready",
                        "Urgency": "NoDisruption"
                    },
                    "related_properties": {}
                },
                {
                    "entity_type": "Incident",
                    "properties": {
                        "Id": "17650",
                        "LastUpdateTime": 1635247508242,
                        "Status": "Ready",
                        "Urgency": "SlightDisruption"
                    },
                    "related_properties": {}
                },
                {
                    "entity_type": "Incident",
                    "properties": {
                        "Id": "17647",
                        "LastUpdateTime": 1635247121852,
                        "Status": "Ready",
                        "Urgency": "NoDisruption"
                    },
                    "related_properties": {}
                }
            ],
            "Query": {
                "completion_status": "OK",
                "errorDetailsList": [],
                "errorDetailsMetaList": [],
                "query_time": 1635341363698808,
                "total_count": 47
            }
        }
    }
}
```

#### Human Readable Output

>### Result Details:
>|Id|LastUpdateTime|Status|Type|Urgency|
>|---|---|---|---|---|
>| 17658 | 1635338444483 | Ready | Incident | NoDisruption |
>| 17656 | 1635331698499 | Ready | Incident | SlightDisruption |
>| 17652 | 1635256251981 | Ready | Incident | NoDisruption |
>| 17650 | 1635247508242 | Ready | Incident | SlightDisruption |
>| 17647 | 1635247121852 | Ready | Incident | NoDisruption |


### microfocus-smax-create-entities
***
Create new entities


#### Base Command

`microfocus-smax-create-entities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entities | A list of new entity objects to creates, please review the Bulk API documentation for more information. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicroFocus.SMAX.Entities.properties.Id | String | Entity Id | 
| MicroFocus.SMAX.Entities.properties.Name | String | Entity name | 
| MicroFocus.SMAX.Entities.properties.completion_status | String | Query result status | 


#### Command Example
```!microfocus-smax-create-entities entities=`[ { "entity_type": "Incident", "properties": { "DisplayLabel": "Test incident", "Description": "Test incident description", "RegisteredForActualService": "11639", "Urgency": "NoDisruption" } } ]````

#### Context Example
```json
{
    "MicroFocus": {
        "SMAX": {
            "Entities": {
                "completion_status": "OK",
                "entity_type": "Incident",
                "properties": {
                    "Id": "17013",
                    "LastUpdateTime": 1635341339329
                },
                "related_properties": {}
            }
        }
    }
}
```

#### Human Readable Output

>### Entities Creation Details:
>|CompletionStatus|Id|LastUpdateTime|Type|
>|---|---|---|---|
>| OK | 17013 | 1635341339329 | Incident |


### microfocus-smax-update-entities
***
Update entities


#### Base Command

`microfocus-smax-update-entities`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entities | A list of updated entity objects, please review the Bulk API documentation for more information. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicroFocus.SMAX.Entities.properties.Id | String | Entity Id | 
| MicroFocus.SMAX.Entities.properties.Name | String | Entity name | 
| MicroFocus.SMAX.Entities.properties.completion_status | String | Query result status | 


#### Command Example
```!microfocus-smax-update-entities entities=`[ { "entity_type": "Incident", "properties": { "Id": "16989", "Description": "Test Description" } } ]````

#### Context Example
```json
{
    "MicroFocus": {
        "SMAX": {
            "Entities": {
                "completion_status": "OK",
                "entity_type": "Incident",
                "properties": {
                    "Id": "16989",
                    "LastUpdateTime": 1635339214960
                },
                "related_properties": {}
            }
        }
    }
}
```

#### Human Readable Output

>### Entities Update Details:
>|CompletionStatus|Id|LastUpdateTime|Type|
>|---|---|---|---|
>| OK | 16989 | 1635339214960 | Incident |


### microfocus-smax-create-incident
***
Create a new incident


#### Base Command

`microfocus-smax-create-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_name | Incident name. | Required | 
| incident_description | Incident description. | Required | 
| impacted_service | Impacted service by the incident, you must provide a service id. | Required | 
| requested_by | Incident requested by, you must provide a user id. | Optional | 
| incident_urgency | Incident urgency level. Possible values are: NoDisruption, SlightDisruption, SevereDisruption, TotalLossOfService. | Optional | 
| impact_scope | Incident impact scope. Possible values are: SingleUser, MultipleUsers, SiteOrDepartment, Enterprise. | Optional | 
| service_desk_group | Service desk group, you have to provide a group id. | Optional | 
| other_properities | An object of other properities. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicroFocus.SMAX.Entities.properties.Id | String | Entity Id | 
| MicroFocus.SMAX.Entities.properties.Name | String | Entity name | 
| MicroFocus.SMAX.Entities.properties.completion_status | String | Query result status | 


#### Command Example
```!microfocus-smax-create-incident incident_name="Test incident" incident_description="Test incident description" impacted_service="11639" other_properities=`{"Status": "Ready","Urgency": "NoDisruption"}````

#### Context Example
```json
{
    "MicroFocus": {
        "SMAX": {
            "Entities": {
                "completion_status": "OK",
                "entity_type": "Incident",
                "properties": {
                    "Id": "17015",
                    "LastUpdateTime": 1635341345342
                },
                "related_properties": {}
            }
        }
    }
}
```

#### Human Readable Output

>### Incident Creation Results:
>|CompletionStatus|Id|LastUpdateTime|Type|
>|---|---|---|---|
>| OK | 17015 | 1635341345342 | Incident |


### microfocus-smax-update-incident
***
Update an incident


#### Base Command

`microfocus-smax-update-incident`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| incident_id | Incident Id. | Required | 
| incident_description | Incident description. | Optional | 
| incident_urgency | Incident urgency level. Possible values are: NoDisruption, SlightDisruption, SevereDisruption, TotalLossOfService. | Optional | 
| impact_scope | Incident impact scope. Possible values are: SingleUser, MultipleUsers, SiteOrDepartment, Enterprise. | Optional | 
| incident_status | Incident status. Possible values are: Ready, InProgress, Pending, Suspended, Complete. | Optional | 
| incident_closure_category | Incident closure category, you have to provide a category Id. | Optional | 
| incident_completion_code | Incident completion code. | Optional | 
| incident_solution | Incident solution details. | Optional | 
| other_properities | An object of other properities. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicroFocus.SMAX.Entities.properties.Id | String | Entity Id | 
| MicroFocus.SMAX.Entities.properties.Name | String | Entity name | 
| MicroFocus.SMAX.Entities.properties.completion_status | String | Query result status | 


#### Command Example
```!microfocus-smax-update-incident incident_id="17007" incident_description="Test Description" incident_status="Complete" incident_solution="Test Solution"```

#### Context Example
```json
{
    "MicroFocus": {
        "SMAX": {
            "Entities": {
                "completion_status": "OK",
                "entity_type": "Incident",
                "properties": {
                    "Id": "17007",
                    "LastUpdateTime": 1635339537768
                },
                "related_properties": {}
            }
        }
    }
}
```

#### Human Readable Output

>### Incident Update Results:
>|CompletionStatus|Id|LastUpdateTime|Type|
>|---|---|---|---|
>| OK | 17007 | 1635339537768 | Incident |


### microfocus-smax-create-request
***
Create a new request


#### Base Command

`microfocus-smax-create-request`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_name | Request name. | Required | 
| request_description | Request description. | Required | 
| requested_by | Requested by, you must provide a user id. | Required | 
| requested_for | Requested for, you must provide a user id. | Required | 
| request_urgency | Request urgency level. Possible values are: NoDisruption, SlightDisruption, SevereDisruption, TotalLossOfService. | Optional | 
| impact_scope | Request impact scope. Possible values are: SingleUser, MultipleUsers, SiteOrDepartment, Enterprise. | Optional | 
| other_properities | An object of other properities. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicroFocus.SMAX.Entities.properties.Id | String | Entity Id | 
| MicroFocus.SMAX.Entities.properties.Name | String | Entity name | 
| MicroFocus.SMAX.Entities.properties.completion_status | String | Query result status | 


#### Command Example
```!microfocus-smax-create-request request_name="Test Request" request_description="Test Request Description" requested_by="10388" requested_for="10388"```

#### Context Example
```json
{
    "MicroFocus": {
        "SMAX": {
            "Entities": {
                "completion_status": "OK",
                "entity_type": "Request",
                "properties": {
                    "Id": "17549",
                    "LastUpdateTime": 1635341351250
                },
                "related_properties": {}
            }
        }
    }
}
```

#### Human Readable Output

>### Request Creation Results:
>|CompletionStatus|Id|LastUpdateTime|Type|
>|---|---|---|---|
>| OK | 17549 | 1635341351250 | Request |


### microfocus-smax-update-request
***
Update a request


#### Base Command

`microfocus-smax-update-request`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| request_id | Request Id. | Required | 
| request_description | Request description. | Optional | 
| request_urgency | Request urgency level. Possible values are: NoDisruption, SlightDisruption, SevereDisruption, TotalLossOfService. | Optional | 
| impact_scope | Incident impact scope. Possible values are: SingleUser, MultipleUsers, SiteOrDepartment, Enterprise. | Optional | 
| request_status | Request status. Possible values are: RequestStatusReady, RequestStatusInProgress, RequestStatusPending, RequestStatusSuspended, RequestStatusComplete, RequestStatusPendingParent, RequestStatusRejected, RequestStatusPendingVendor, RequestStatusPendingExternalServiceDesk, RequestStatusPendingSpecialOperation. | Optional | 
| request_note | Request update note. | Optional | 
| other_properities | An object of other properities. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MicroFocus.SMAX.Entities.properties.Id | String | Entity Id | 
| MicroFocus.SMAX.Entities.properties.Name | String | Entity name | 
| MicroFocus.SMAX.Entities.properties.completion_status | String | Query result status | 


#### Command Example
```!microfocus-smax-update-request request_id="17009" request_description="Test Description" request_status="RequestStatusPendingSpecialOperation"```

#### Context Example
```json
{
    "MicroFocus": {
        "SMAX": {
            "Entities": {
                "completion_status": "OK",
                "entity_type": "Request",
                "properties": {
                    "Id": "17009",
                    "LastUpdateTime": 1635339631068
                },
                "related_properties": {}
            }
        }
    }
}
```

#### Human Readable Output

>### Request Update Results:
>|CompletionStatus|Id|LastUpdateTime|Type|
>|---|---|---|---|
>| OK | 17009 | 1635339631068 | Request |
