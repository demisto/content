Azure Risky Users provides access to all at-risk users and risk detections in Azure AD environment.
This integration was integrated and tested with version 1.0 of Microsoft Graph Azure Risky Users.
# Self-Deployed Application
To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal.

The application must have the following permissions:
- *IdentityRiskEvent.Read.All*
- *IdentityRiskEvent.ReadWrite.All*
- *IdentityRiskyUser.Read.All*
- *IdentityRiskyUser.ReadWrite.All*
- *User.Read*

In case you want to use Device code flow, you must allow public client flows (can be found under the **Authentication** section of the app).

## Authentication Using the Client Credentials Flow (recommended)

Follow these steps for a self-deployed configuration:

1. To use a self-configured Azure application, you need to add a new Azure App Registration in the Azure Portal. To add the registration, refer to the following [Microsoft article](https://docs.microsoft.com/en-us/microsoft-365/security/defender/api-create-app-web?view=o365-worldwide#create-an-app) steps 1-8.
2. Select the **client-credentials** Authentication Type.
3. Enter your Client/Application ID in the *Application ID* parameter. 
4. Enter your Client Secret in the *Client Secret* parameter.
5. Enter your Tenant ID in the *Tenant ID* parameter.
6. Save the instance.
7. Run the ***!azure-risky-users-auth-test*** command - a 'Success' message should be printed to the War Room.


## Authentication Using the Device Code Flow

Follow these steps for a self-deployed configuration:

1. Fill in the required parameters.
2. Run the ***!azure-risky-users-auth-start*** command.
3. Follow the instructions that appear.
4. Run the ***!azure-risky-users-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully.


# Cortex XSOAR Application
In order to use the Cortex XSOAR Azure application, 
use the Client ID - (application_id) (**ec854987-95fa-4c8f-8056-768dd0f409ac**).

## Authentication Using the Device Code Flow -
In order to connect to the Azure Risky Users using the Cortex XSOAR Azure App with Device Code flow authentication. See [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code).

1. Fill in the required parameters - use the above mentioned Client ID - (application_id).
2. Run the ***!azure-risky-users-auth-start*** command.
3. Follow the instructions that appear.
4. Run the ***!azure-risky-users-auth-complete*** command.

At end of the process you'll see a message that you've logged in successfully.


## Configure AzureRiskyUsers on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AzureRiskyUsers.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Client ID | True |
    | Authentication Type | True |
    | Tenant ID (for Client Credentials mode) | False |
    | Client Secret (for Client Credentials mode) | False |
    | Azure Managed Identities Client ID | False |
    | Use system proxy | False |
    | Trust any certificate | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-risky-users-auth-test
***
Tests the connectivity to Azure.


#### Base Command

`azure-risky-users-auth-test`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-risky-users-auth-test```

#### Human Readable Output

> Success!

### azure-risky-users-auth-start
***
Run this command to start the authorization process and follow the instructions in the command results.


#### Base Command

`azure-risky-users-auth-start`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-risky-users-auth-start```

#### Human Readable Output

>### Authorization instructions
>1. To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code XXXXX to authenticate.
>2. Run the ***!azure-risky-users-auth-complete*** command in the War Room.

### azure-risky-users-auth-complete
***
Run this command to complete the authorization process. Should be used after running the azure-risky-users-auth-start command.


#### Base Command

`azure-risky-users-auth-complete`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-risky-users-auth-complete```

#### Human Readable Output

> Authorization completed successfully.

### azure-risky-users-auth-reset
***
Run this command if for some reason you need to rerun the authentication process.


#### Base Command

`azure-risky-users-auth-reset`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-risky-users-auth-reset```

#### Human Readable Output

>Authorization was reset successfully. Run **!azure-risky-users-auth-start** to start the authentication process.

### azure-risky-users-list

***
Returns a list of all risky users and their properties.

#### Base Command

`azure-risky-users-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| risk_state | Sets the Risk State to retrieve. Possible values are: atRisk, confirmedCompromised, remediated, dismissed. | Optional | 
| limit | Limit of results to retrieve. Default is 50. | Optional | 
| page | Page number. | Optional | 
| page_size | Amount of results per request. Value can be between 1 and 500. When only page_size is given, the first page results will be fetched. | Optional | 
| next_token | The URL for the next set of items to return during pagination. (This URL can be retrieved from a previous call). | Optional | 
| risk_level | Sets the Risk Level to retrieve. Possible values are: low, medium, high. | Optional | 
| order_by | The method used to order the retrieved results. Possible values are: riskLastUpdatedDateTime desc, riskLastUpdatedDateTime asc. Default is riskLastUpdatedDateTime desc. | Optional | 
| updated_before | Displays all RiskyUsers before a specific datetime. For Example "2024-02-27T04:49:26.257525Z", "10 days", "5 months", "2 hours". | Optional | 
| updated_after | Displays all RiskyUsers after a specific datetime. For Example "2024-02-27T04:49:26.257525Z", "10 days", "5 months", "2 hours". | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureRiskyUsers.RiskyUser.id | String | Unique ID of the user at risk. | 
| AzureRiskyUsers.RiskyUser.userDisplayName | String | Risky user display name. | 
| AzureRiskyUsers.RiskyUser.userPrincipalName | String | Risky user principal name. | 
| AzureRiskyUsers.RiskyUser.riskLevel | String | Level of the detected risky user. Possible values are: low, medium, high, hidden, none, unknownFutureValue. | 
| AzureRiskyUsers.RiskyUser.riskState | String | State of the user's risk. Possible values are: none, confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised. | 
| AzureRiskyUsers.RiskyUser.riskLastUpdatedDateTime | Date | The date and time that the risky user was last updated. The DateTimeOffset type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: 2014-01-01T00:00:00Z. | 
| AzureRiskyUsers.RiskyUser.isDeleted | Boolean | Indicates whether the user is deleted. | 
| AzureRiskyUsers.RiskyUser.isProcessing | Boolean | Indicates whether a user's risky state is being processed by the backend. | 
| AzureRiskyUsers.RiskyUser.riskDetail | String | Details of the detected risk. Possible values are: none, adminGeneratedTemporaryPassword, userPerformedSecuredPasswordChange, userPerformedSecuredPasswordReset, adminConfirmedSigninSafe, aiConfirmedSigninSafe, userPassedMFADrivenByRiskBasedPolicy, adminDismissedAllRiskForUser, adminConfirmedSigninCompromised, hidden, adminConfirmedUserCompromised, unknownFutureValue. | 
| AzureRiskyUsers.RiskyUserListNextToken | String | A property in the response that contains a URL to the next page of results. | 


#### Command example
```!azure-risky-users-list page_size=2```
#### Context Example
```json
{
    "AzureRiskyUsers": {
        "RiskyUser": [
            {
                "id": "ID_1",
                "isDeleted": false,
                "isProcessing": false,
                "riskDetail": "none",
                "riskLastUpdatedDateTime": "2023-06-04T10:12:39.3625926Z",
                "riskLevel": "medium",
                "riskState": "atRisk",
                "userDisplayName": "user Display Name",
                "userPrincipalName": "User Principal Name"
            },
            {
                "id": "ID_2",
                "isDeleted": false,
                "isProcessing": false,
                "riskDetail": "none",
                "riskLastUpdatedDateTime": "2022-02-23T17:50:40.3408199Z",
                "riskLevel": "high",
                "riskState": "atRisk",
                "userDisplayName": "user Display Name",
                "userPrincipalName": "User Principal Name"
            },
        ],
        "RiskyUserListNextToken": "token",
    }
}
```

#### Human Readable Output

>### Risky Users List:
>|Id|User Display Name|User Principal Name|Risk Level|Risk State|Risk Detail|Risk Last Updated Date Time|
>|---|---|---|---|---|---|---|
>| ID_1 | user Display Name | User Principal Name | medium | atRisk | none | 2023-06-04T10:12:39.3625926Z |
>| ID_2 | user Display Name | User Principal Name | high | atRisk | none | 2022-02-23T17:50:40.3408199Z |

>### Risky Users List Token:
>|next_token|
>|---|
>| token |


### azure-risky-user-get
***
Retrieve properties and relationships of a Risky User.


#### Base Command

`azure-risky-user-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Risky user ID to retrieve. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureRiskyUsers.RiskyUser.id | String | Unique ID of the user at risk. |
| AzureRiskyUsers.RiskyUser.userDisplayName | String | Risky user display name. |
| AzureRiskyUsers.RiskyUser.userPrincipalName | String | Risky user principal name. |
| AzureRiskyUsers.RiskyUser.riskLevel | String | Level of the detected risky user. Possible values are: low, medium, high, hidden, none, unknownFutureValue. |
| AzureRiskyUsers.RiskyUser.riskState | String | State of the user's risk. Possible values are: none, confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised. |
| AzureRiskyUsers.RiskyUser.riskLastUpdatedDateTime | Date | The date and time that the risky user was last updated. The DateTimeOffset type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: 2014-01-01T00:00:00Z |
| AzureRiskyUsers.RiskyUser.isDeleted | Boolean | Indicates whether the user is deleted. |
| AzureRiskyUsers.RiskyUser.isProcessing | Boolean | Indicates whether a user's risky state is being processed by the backend. |
| AzureRiskyUsers.RiskyUser.riskDetail | String | Details of the detected risk. Possible values are: none, adminGeneratedTemporaryPassword, userPerformedSecuredPasswordChange, userPerformedSecuredPasswordReset, adminConfirmedSigninSafe, aiConfirmedSigninSafe, userPassedMFADrivenByRiskBasedPolicy, adminDismissedAllRiskForUser, adminConfirmedSigninCompromised, hidden, adminConfirmedUserCompromised, unknownFutureValue. |


#### Command Example
```!azure-risky-user-get id=333```

#### Context Example
```json
{
    "AzureRiskyUsers": {
        "RiskyUser": {
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identityProtection/riskyUsers/$entity",
            "id": "333",
            "isDeleted": false,
            "isProcessing": false,
            "riskDetail": "userPerformedSecuredPasswordReset",
            "riskLastUpdatedDateTime": "2020-10-05T12:12:17.2115592Z",
            "riskLevel": "none",
            "riskState": "remediated",
            "userDisplayName": "Yossi Israeli",
            "userPrincipalName": "yossi@test.com"
        }
    }
}
```

#### Human Readable Output

>### Found Risky User With ID: 333
>|Id|User Display Name|User Principal Name|Risk Level|Risk State|Risk Detail|Risk Last Updated Date Time|
>|---|---|---|---|---|---|---|
>| 333 | Yossi Israeli | yossi@test.com | none | remediated | userPerformedSecuredPasswordReset | 2020-10-05T12:12:17.2115592Z |


### azure-risky-users-risk-detections-list
***
Get a list of the riskDetection objects and their properties.


#### Base Command

`azure-risky-users-risk-detections-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Limit of results to retrieve. Default is 50. | Optional |
| page | Page number. Default is 1. | Optional |
| risk_state | Risk State to retrieve. If not specified, all states will be retrieved. Possible values are: atRisk, confirmedCompromised, remediated, dismissed, confirmedSafe. | Optional |
| risk_level | Specify to get only results with the same Risk Level. Possible values are: low, medium, high. | Optional |
| detected_date_time_before | Filter events that created before specific time range starting, e.g. 2022-06-09T23:00:44.7420905Z. | Optional |
| detected_date_time_after | Filter events that created after specific time range starting, e.g. 2022-06-09T23:00:44.7420905Z. | Optional |
| order_by | The method used to order the retrieved results. | Optional |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureRiskyUsers.RiskDetection.id | String | Unique ID of the risk detection. Inherited from entity. |
| AzureRiskyUsers.RiskDetection.userId | String | Unique ID of the user. |
| AzureRiskyUsers.RiskDetection.userDisplayName | String | The user display name of the user. |
| AzureRiskyUsers.RiskDetection.userPrincipalName | String | The user principal name \(UPN\) of the user. |
| AzureRiskyUsers.RiskDetection.riskDetail | String | Details of the detected risk. Possible values are: none, adminGeneratedTemporaryPassword, userPerformedSecuredPasswordChange, userPerformedSecuredPasswordReset, adminConfirmedSigninSafe, aiConfirmedSigninSafe, userPassedMFADrivenByRiskBasedPolicy, adminDismissedAllRiskForUser, adminConfirmedSigninCompromised, hidden, adminConfirmedUserCompromised, unknownFutureValue. |
| AzureRiskyUsers.RiskDetection.riskEventType | String | The type of risk event detected. The possible values are unlikelyTravel, anonymizedIPAddress, maliciousIPAddress, unfamiliarFeatures, malwareInfectedIPAddress, suspiciousIPAddress, leakedCredentials, investigationsThreatIntelligence, generic,adminConfirmedUserCompromised, mcasImpossibleTravel, mcasSuspiciousInboxManipulationRules, investigationsThreatIntelligenceSigninLinked, maliciousIPAddressValidCredentialsBlockedIP, and unknownFutureValue. If the risk detection is a premium detection, will show generic |
| AzureRiskyUsers.RiskDetection.riskLevel | String | Level of the detected risk. Possible values are: low, medium, high, hidden, none, unknownFutureValue. |
| AzureRiskyUsers.RiskDetection.riskState | String | The state of a detected risky user or sign-in. Possible values are: none, confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised, unknownFutureValue. |
| AzureRiskyUsers.RiskDetection.ipAddress | String | Provides the IP address of the client from where the risk occurred. |
| AzureRiskyUsers.RiskDetection.source | String | Source of the risk detection. For example, activeDirectory. |
| AzureRiskyUsers.RiskDetection.detectionTimingType | String | Timing of the detected risk \(real-time/offline\). Possible values are: notDefined, realtime, nearRealtime, offline, unknownFutureValue. |
| AzureRiskyUsers.RiskDetection.lastUpdatedDateTime | Date | Date and time that the risk detection was last updated. The DateTimeOffset type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is look like this: 2014-01-01T00:00:00Z |
| AzureRiskyUsers.RiskDetection.location | String | Location of the sign-in. |
| AzureRiskyUsers.RiskDetection.activity | String | Indicates the activity type the detected risk is linked to. . Possible values are: signin, user, unknownFutureValue. |
| AzureRiskyUsers.RiskDetection.activityDateTime | Date | Date and time that the risky activity occurred. The DateTimeOffset type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is look like this: 2014-01-01T00:00:00Z |
| AzureRiskyUsers.RiskDetection.additionalInfo | String | Additional information associated with the risk detection in JSON format. |
| AzureRiskyUsers.RiskDetection.correlationId | String | Correlation ID of the sign-in associated with the risk detection. This property is null if the risk detection is not associated with a sign-in. |
| AzureRiskyUsers.RiskDetection.detectedDateTime | Date | Date and time that the risk was detected. The DateTimeOffset type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is look like this: 2014-01-01T00:00:00Z |
| AzureRiskyUsers.RiskDetection.requestId | String | Request ID of the sign-in associated with the risk detection. This property is null if the risk detection is not associated with a sign-in. |
| AzureRiskyUsers.RiskDetection.tokenIssuerType | String | Indicates the type of token issuer for the detected sign-in risk. Possible values are: AzureAD, ADFederationServices, UnknownFutureValue. |


#### Command Example
```!azure-risky-users-risk-detections-list limit=2```

#### Context Example
```json
{
    "AzureRiskyUsers": {
        "RiskDetection": [
            {
                "activity": "signin",
                "activityDateTime": "2021-06-20T03:51:32.9572792Z",
                "additionalInfo": "[{\"Key\":\"userAgent\",\"Value\":\"Dalvik/2.1.0 (Linux; U; Android 9; VKY-L29 Build/HUAWEIVKY-L29) ;VKY-L29\"}]",
                "correlationId": "aaaa1111",
                "detectedDateTime": "2021-06-20T03:51:32.9572792Z",
                "detectionTimingType": "realtime",
                "id": "555",
                "ipAddress": "1.1.1.1",
                "lastUpdatedDateTime": "2021-06-20T03:53:58.853418Z",
                "location": {
                    "city": "Pisgat Ze'ev",
                    "countryOrRegion": "IL",
                    "geoCoordinates": {
                        "latitude": 31,
                        "longitude": 35
                    },
                    "state": "Yerushalayim"
                },
                "requestId": "bbbb1111",
                "riskDetail": "userPassedMFADrivenByRiskBasedPolicy",
                "riskEventType": "unfamiliarFeatures",
                "riskLevel": "low",
                "riskState": "remediated",
                "source": "IdentityProtection",
                "tokenIssuerType": "AzureAD",
                "userDisplayName": "Shalev Israeli",
                "userId": "777",
                "userPrincipalName": "ShalevI@test.com"
            },
            {
                "activity": "signin",
                "activityDateTime": "2021-06-27T19:16:19.9976898Z",
                "additionalInfo": "[{\"Key\":\"userAgent\",\"Value\":\"Dalvik/2.1.0 (Linux; U; Android 9; SM-G950F Build/PPR1.180610.011) ;SM-G950F\"}]",
                "correlationId": "aaaa2222",
                "detectedDateTime": "2021-06-27T19:16:19.9976898Z",
                "detectionTimingType": "realtime",
                "id": "888",
                "ipAddress": "1.1.1.1",
                "lastUpdatedDateTime": "2021-06-27T19:19:44.4975416Z",
                "location": {
                    "city": "Dniprodzerzhyns'k",
                    "countryOrRegion": "UA",
                    "geoCoordinates": {
                        "latitude": 48,
                        "longitude": 34
                    },
                    "state": "Dnipropetrovs'ka Oblast'"
                },
                "requestId": "bbbb2222",
                "riskDetail": "userPassedMFADrivenByRiskBasedPolicy",
                "riskEventType": "unfamiliarFeatures",
                "riskLevel": "low",
                "riskState": "remediated",
                "source": "IdentityProtection",
                "tokenIssuerType": "AzureAD",
                "userDisplayName": "Svetlana Israeli",
                "userId": "999",
                "userPrincipalName": "SvetlanaI@test.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Risk Detections List
>Current page size: 2
>Showing page 1 out others that may exist
>|Id|User Id|User Display Name|User Principal Name|Risk Detail|Risk Event Type|Risk Level|Risk State|Risk Detail|Last Updated Date Time|Ip Address|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 555 | 777 | Shalev Israeli | ShalevI@test.com | userPassedMFADrivenByRiskBasedPolicy | unfamiliarFeatures | low | remediated | userPassedMFADrivenByRiskBasedPolicy | 2021-06-20T03:53:58.853418Z | 1.1.1.1 |
>| 888 | 999 | Svetlana Israeli | SvetlanaI@test.com | userPassedMFADrivenByRiskBasedPolicy | unfamiliarFeatures | low | remediated | userPassedMFADrivenByRiskBasedPolicy | 2021-06-27T19:19:44.4975416Z | 1.1.1.1 |


### azure-risky-users-risk-detection-get
***
Read the properties and relationships of a riskDetection object.


#### Base Command

`azure-risky-users-risk-detection-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of risk detection to retrieve. | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AzureRiskyUsers.RiskDetection.id | String | Unique ID of the risk detection. Inherited from entity. |
| AzureRiskyUsers.RiskDetection.userId | String | Unique ID of the user. |
| AzureRiskyUsers.RiskDetection.userDisplayName | String | The user display name of the user. |
| AzureRiskyUsers.RiskDetection.userPrincipalName | String | The user principal name \(UPN\) of the user. |
| AzureRiskyUsers.RiskDetection.riskDetail | String | Details of the detected risk. Possible values are: none, adminGeneratedTemporaryPassword, userPerformedSecuredPasswordChange, userPerformedSecuredPasswordReset, adminConfirmedSigninSafe, aiConfirmedSigninSafe, userPassedMFADrivenByRiskBasedPolicy, adminDismissedAllRiskForUser, adminConfirmedSigninCompromised, hidden, adminConfirmedUserCompromised, unknownFutureValue. |
| AzureRiskyUsers.RiskDetection.riskEventType | String | The type of risk event detected. The possible values are unlikelyTravel, anonymizedIPAddress, maliciousIPAddress, unfamiliarFeatures, malwareInfectedIPAddress, suspiciousIPAddress, leakedCredentials, investigationsThreatIntelligence, generic,adminConfirmedUserCompromised, mcasImpossibleTravel, mcasSuspiciousInboxManipulationRules, investigationsThreatIntelligenceSigninLinked, maliciousIPAddressValidCredentialsBlockedIP, and unknownFutureValue. If the risk detection is a premium detection, will show generic |
| AzureRiskyUsers.RiskDetection.riskLevel | String | Level of the detected risk. Possible values are: low, medium, high, hidden, none, unknownFutureValue. |
| AzureRiskyUsers.RiskDetection.riskState | String | The state of a detected risky user or sign-in. Possible values are: none, confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised, unknownFutureValue. |
| AzureRiskyUsers.RiskDetection.ipAddress | String | Provides the IP address of the client from where the risk occurred. |
| AzureRiskyUsers.RiskDetection.source | String | Source of the risk detection. For example, activeDirectory. |
| AzureRiskyUsers.RiskDetection.detectionTimingType | String | Timing of the detected risk \(real-time/offline\). Possible values are: notDefined, realtime, nearRealtime, offline, unknownFutureValue. |
| AzureRiskyUsers.RiskDetection.lastUpdatedDateTime | Date | Date and time that the risk detection was last updated. The DateTimeOffset type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is look like this: 2014-01-01T00:00:00Z |
| AzureRiskyUsers.RiskDetection.location | String | Location of the sign-in. |
| AzureRiskyUsers.RiskDetection.activity | String | Indicates the activity type the detected risk is linked to. . Possible values are: signin, user, unknownFutureValue. |
| AzureRiskyUsers.RiskDetection.activityDateTime | Date | Date and time that the risky activity occurred. The DateTimeOffset type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is look like this: 2014-01-01T00:00:00Z |
| AzureRiskyUsers.RiskDetection.additionalInfo | String | Additional information associated with the risk detection in JSON format. |
| AzureRiskyUsers.RiskDetection.correlationId | String | Correlation ID of the sign-in associated with the risk detection. This property is null if the risk detection is not associated with a sign-in. |
| AzureRiskyUsers.RiskDetection.detectedDateTime | Date | Date and time that the risk was detected. The DateTimeOffset type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 is look like this: 2014-01-01T00:00:00Z |
| AzureRiskyUsers.RiskDetection.requestId | String | Request ID of the sign-in associated with the risk detection. This property is null if the risk detection is not associated with a sign-in. |
| AzureRiskyUsers.RiskDetection.tokenIssuerType | String | Indicates the type of token issuer for the detected sign-in risk. Possible values are: AzureAD, ADFederationServices, UnknownFutureValue. |


#### Command Example
```!azure-risky-users-risk-detection-get id=6565```

#### Context Example
```json
{
    "AzureRiskyUsers": {
        "RiskDetection": {
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identityProtection/riskDetections/$entity",
            "activity": "signin",
            "activityDateTime": "2021-07-03T13:35:38.8773806Z",
            "additionalInfo": "[{\"Key\":\"userAgent\",\"Value\":\"Dalvik/2.1.0 (Linux; U; Android 9; SM-G950F Build/PPR1.180610.011) ;SM-G950F\"}]",
            "correlationId": "aaaa3333",
            "detectedDateTime": "2021-07-03T13:35:38.8773806Z",
            "detectionTimingType": "realtime",
            "id": "6565",
            "ipAddress": "3.3.3.3",
            "lastUpdatedDateTime": "2021-07-03T13:38:04.6531838Z",
            "location": {
                "city": "Lviv",
                "countryOrRegion": "UA",
                "geoCoordinates": {
                    "latitude": 49,
                    "longitude": 24
                },
                "state": "L'vivs'ka Oblast'"
            },
            "requestId": "bbbb33333",
            "riskDetail": "userPassedMFADrivenByRiskBasedPolicy",
            "riskEventType": "unfamiliarFeatures",
            "riskLevel": "low",
            "riskState": "remediated",
            "source": "IdentityProtection",
            "tokenIssuerType": "AzureAD",
            "userDisplayName": "Svetlana Israeli",
            "userId": "999",
            "userPrincipalName": "SvetlanaI@test.com"
        }
    }
}
```

#### Human Readable Output

>### Found Risk Detection with ID: 6565
>|Id|User Id|User Display Name|User Principal Name|Risk Detail|Risk Event Type|Risk Level|Risk State|Ip Address|Detection Timing Type|Last Updated Date Time|Location|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 6565 | 999 | Svetlana Israeli | SvetlanaI@test.com | userPassedMFADrivenByRiskBasedPolicy | unfamiliarFeatures | low | remediated | 3.3.3.3 | realtime | 2021-07-03T13:38:04.6531838Z | city: Lviv<br/>state: L'vivs'ka Oblast'<br/>countryOrRegion: UA<br/>geoCoordinates: {"latitude": 49, "longitude": 24} |
