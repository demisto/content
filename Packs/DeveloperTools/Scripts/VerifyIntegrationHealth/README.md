Checks for existing errors in a given integration.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| integration_name | Integration name to check its health status. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| IntegrationHealth.isHealthy | Determines the health status of the integration. | Boolean |
| IntegrationHealth.fetchDone | Determines whether the fetch-indicators command completed. | Boolean |
| IntegrationHealth.integrationName | Requested integration name. | String |


## Script Example
```!VerifyIntegrationHealth integration_name="AutoFocus Daily Feed"```

## Context Example
```json
{
    "IntegrationHealth": {
        "fetchDone": true,
        "integrationName": "AutoFocus Daily Feed",
        "isHealthy": true
    }
}
```

## Human Readable Output

>### Results
>|fetchDone|integrationName|isHealthy|
>|---|---|---|
>| true | AutoFocus Daily Feed | true |

### Troubleshooting
Multi-tenant environments should be configured with the Cortex Rest API instance when using this 
automation. Make sure the *Use tenant* parameter (in the Cortex Rest API integration) is checked 
to ensure that API calls are made to the current tenant instead of the master tenant.