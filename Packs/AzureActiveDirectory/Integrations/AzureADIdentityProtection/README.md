Gets information from the Azure Active Directory Identity Protection service.
This integration was integrated and tested with the beta version of Azure Active Directory Identity Protection API.

## Required Permissions
To use this integration, the following permissions are required on the Azure app.  
- `IdentityRiskEvent.Read.All` 
- `IdentityRiskyUser.ReadWrite.All`
- `User.Read`

## Authorization
Choose between the following Azure app options. Both of them use the [device authorization grant flow](https://docs.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-device-code).

#### Cortex XSOAR Azure app
To use the Cortex XSOAR Azure app, use the default application ID `4ffef4a4-601f-4393-a789-432f3f3b8470` and fill in your subscription ID.

#### Self Deployed Azure app 
To use a self-deployed Azure app, add a new Azure App Registration in the Azure Portal
1. The app must allow public client flows (which can be found under the **Authentication** section of the app).
2. The app must be multi-tenant.
3. The app should be granted the permissions listed in the [required permissions](#required-permissions) section above. 

## Configure Azure Active Directory Identity Protection on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Active Directory Identity Protection.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Application ID | The ID of the managed application. | True |
    | Subscription ID | The Azure Active Directory subscription ID, found on the Azure Portal. | True |
    | Azure Active Directory endpoint | The Azure Active Directory endpoint associated with a national cloud. | True |
    | Trust any certificate (not secure) | When selected, certificates are not checked.  | False |
    | Use system proxy settings | When selected, runs the integration instance using a proxy server (https or http) that you defined in the server configuration.  | False |
5. Run the **!azure-ad-auth-start** command to start the connection process.
6. Follow the instructions shown. The last of them should be running the **!azure-ad-auth-complete** command.
7. Run the **!azure-ad-auth-test** command to validate the URLs, token, and connection.
    
#### Base Command

`azure-ad-auth-test`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-ad-auth-test```

#### Human Readable Output

>✅ Success!

### azure-ad-auth-start
***
Run this command to start the authorization process and follow the instructions shown.


#### Base Command

`azure-ad-auth-start`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-ad-auth-start```

#### Human Readable Output

>### Authorization instructions
>1. To sign in, use a web browser to open the page [https:<span>//</span>microsoft.com/devicelogin](https:<span>//</span>microsoft.com/devicelogin)
>and enter the code **EXAMPLE-CODE** to authenticate.
>2. Run the **!azure-ad-auth-complete** command in the War Room.

### azure-ad-auth-complete
***
Run this command to complete the authorization process. This should be used after running the azure-ad-auth-start command.


#### Base Command

`azure-ad-auth-complete`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
``` !azure-ad-auth-complete ```

#### Human Readable Output
```
✅ Authorization completed successfully.
```


### azure-ad-auth-reset
***
Run this command if for some reason you need to rerun the authentication process.


#### Base Command

`azure-ad-auth-reset`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!azure-ad-auth-reset```

#### Human Readable Output

>Authorization was reset successfully. Run **!azure-ad-auth-start** to start the authentication process.

### azure-ad-identity-protection-risks-list
***
Retrieve the properties of a collection of riskDetection objects.

#### Required Permissions
`IdentityRiskEvent.Read.All`

#### Base Command

`azure-ad-identity-protection-risks-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Unique ID of the risk detection. | Optional | 
| user_id | Unique ID of the user. | Optional | 
| user_principal_name | The user principal name (UPN) of the user. | Optional | 
| country | The country or region of the activity. For example, `US` or `UK`. For further details, see https://docs.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-beta. | Optional | 
| filter_expression | A custom query in OData syntax. Using this overrides all arguments, except for next_link. For more details, see https://docs.microsoft.com/en-us/graph/query-parameters. | Optional | 
| limit | Number of results to provide. Default is 50. | Optional | 
| next_link | A link that specifies a starting point for subsequent calls. Using this argument overrides all other arguments. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AADIdentityProtection.Risks.id | string | Unique ID of the risk detection. | 
| AADIdentityProtection.Risks.requestId | string | The ID of the sign-in associated with the risk detection. This property is null if the risk detection is not associated with a sign-in. | 
| AADIdentityProtection.Risks.correlationId | string | Correlation ID of the sign-in associated with the risk detection. This property is null if the risk detection is not associated with a sign-in. | 
| AADIdentityProtection.Risks.riskEventType | string | The type of risk event detected. The possible values are unlikelyTravel, anonymizedIPAddress, maliciousIPAddress, unfamiliarFeatures, malwareInfectedIPAddress, suspiciousIPAddress, leakedCredentials, investigationsThreatIntelligence, generic,adminConfirmedUserCompromised, mcasImpossibleTravel, mcasSuspiciousInboxManipulationRules, investigationsThreatIntelligenceSigninLinked, maliciousIPAddressValidCredentialsBlockedIP, and unknownFutureValue. | 
| AADIdentityProtection.Risks.riskType | string | Deprecated. Use riskEventType instead. List of risk event types. | 
| AADIdentityProtection.Risks.riskLevel | string | Risk level of the detected risky user. The possible values are low, medium, high, hidden, none, and unknownFutureValue. | 
| AADIdentityProtection.Risks.riskState | string | State of the user's risk. The possible values are none, confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised, and unknownFutureValue. | 
| AADIdentityProtection.Risks.riskDetail | string | Reason why the user is considered a risky user. The possible values are limited to none, adminGeneratedTemporaryPassword, userPerformedSecuredPasswordChange, userPerformedSecuredPasswordReset, adminConfirmedSigninSafe, aiConfirmedSigninSafe, userPassedMFADrivenByRiskBasedPolicy, adminDismissedAllRiskForUser, adminConfirmedSigninCompromised, hidden, adminConfirmedUserCompromised, and unknownFutureValue. | 
| AADIdentityProtection.Risks.source | string | Source of the risk detection. For example, `activeDirectory`. | 
| AADIdentityProtection.Risks.detectionTimingType | string | Timing of the detected risk \(real-time/offline\). The possible values are notDefined, realtime, nearRealtime, offline, and unknownFutureValue. | 
| AADIdentityProtection.Risks.activity | string | Indicates the activity type the detected risk is linked to. The possible values are signin, user, and unknownFutureValue. | 
| AADIdentityProtection.Risks.tokenIssuerType | string | Indicates the type of token issuer for the detected sign-in risk. The possible values are AzureAD, ADFederationServices, and unknownFutureValue. | 
| AADIdentityProtection.Risks.ipAddress | string | Provides the IP address of the client from where the risk occurred. | 
| AADIdentityProtection.Risks.location.city | string | City of the sign-in. | 
| AADIdentityProtection.Risks.location.countryOrRegion | string | Country or region of the sign-in. | 
| AADIdentityProtection.Risks.location.geoCoordinates.latitude | string | Latitude of the sign-in. | 
| AADIdentityProtection.Risks.location.geoCoordinates.longitude | string | Longitude of the sign-in. | 
| AADIdentityProtection.Risks.location.state | string | State of the sign-in. | 
| AADIdentityProtection.Risks.activityDateTime | string | Date and time that the risky activity occurred. The DateTimeOffset type represents date and time information using the ISO 8601 format and is always in UTC time. | 
| AADIdentityProtection.Risks.detectedDateTime | string | Date and time that the risk was detected. The DateTimeOffset type represents date and time information using the ISO 8601 format and is always in UTC time. | 
| AADIdentityProtection.Risks.lastUpdatedDateTime | string | Date and time that the risk detection was last updated. The DateTimeOffset type represents date and time information using the ISO 8601 format and is always in UTC time. | 
| AADIdentityProtection.Risks.userId | string | Unique ID of the user. | 
| AADIdentityProtection.Risks.userDisplayName | string | Risky user display name. | 
| AADIdentityProtection.Risks.userPrincipalName | string | Risky user principal name. | 
| AADIdentityProtection.Risks.additionalInfo | string | Additional information associated with the risk detection in JSON format. | 


#### Command Example
```!azure-ad-identity-protection-risks-list```

#### Context Example
```json
{
    "AADIdentityProtection": {
        "Risks": [
            {
                "activity": "signin",
                "activityDateTime": "2021-04-25T09:00:40.7780969Z",
                "additionalInfo": "[{\"Key\":\"userAgent\",\"Value\":\"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36\"}]",
                "correlationId": "271ac223-695b-418e-85b3-7809070ee33e",
                "detectedDateTime": "2021-04-25T09:00:40.7780969Z",
                "detectionTimingType": "realtime",
                "id": "86a45315157fb75c3a6e0936ef854c139df99bdfbde4bd7e7f1bc685c3638908",
                "ipAddress": "1.1.1.1",
                "lastUpdatedDateTime": "2021-05-23T08:20:41.9161522Z",
                "location": {
                    "city": "San Jose",
                    "countryOrRegion": "US",
                    "geoCoordinates": {
                        "latitude": 37.33053,
                        "longitude": -121.8382
                    },
                    "state": "California"
                },
                "requestId": "86b6e4a1-25cb-40c7-af2b-9e79c6106000",
                "riskDetail": "userPerformedSecuredPasswordChange",
                "riskEventType": "unfamiliarFeatures",
                "riskLevel": "low",
                "riskState": "remediated",
                "riskType": "unfamiliarFeatures",
                "source": "IdentityProtection",
                "tokenIssuerType": "AzureAD",
                "userDisplayName": "John Doe",
                "userId": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                "userPrincipalName": "jdoe@example.com"
            },
            {
                "activity": "signin",
                "activityDateTime": "2021-04-28T11:40:11.333738Z",
                "additionalInfo": "[{\"Key\":\"userAgent\",\"Value\":\"python-requests/2.18.4\"}]",
                "correlationId": "6f74b0f4-dabc-49af-aa87-3aaba042baba",
                "detectedDateTime": "2021-04-28T11:40:11.333738Z",
                "detectionTimingType": "realtime",
                "id": "c0e94938cddbb849ef64dbb6a98189ab3d93cdec4c4f95923ac935a91486def2",
                "ipAddress": "2.2.2.2",
                "lastUpdatedDateTime": "2021-05-23T08:20:29.027631Z",
                "location": {
                    "city": "Frankfurt Am Main",
                    "countryOrRegion": "DE",
                    "geoCoordinates": {
                        "latitude": 50.1109,
                        "longitude": 8.6821
                    },
                    "state": "Hessen"
                },
                "requestId": "64b01b65-25fa-4811-b4cd-411c9accc000",
                "riskDetail": "userPerformedSecuredPasswordChange",
                "riskEventType": "unfamiliarFeatures",
                "riskLevel": "low",
                "riskState": "remediated",
                "riskType": "unfamiliarFeatures",
                "source": "IdentityProtection",
                "tokenIssuerType": "AzureAD",
                "userDisplayName": "John Doe",
                "userId": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                "userPrincipalName": "jdoe@example.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Risks (6 results)
>|User ID|User Principal Name|User Display Name|IP Address|Detected Date Time|Activity|Activity Date Time|Additional Info|Correlation ID|Detection Timing Type|ID|Last Updated Date Time|Location|Request ID|Risk Detail|Risk Event Type|Risk Level|Risk State|Risk Type|Source|Token Issuer Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | 1.1.1.1 | 2021-04-25T09:00:40.7780969Z | signin | 2021-04-25T09:00:40.7780969Z | [{"Key":"userAgent","Value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36"}] | 271ac223-695b-418e-85b3-7809070ee33e | realtime | 86a45315157fb75c3a6e0936ef854c139df99bdfbde4bd7e7f1bc685c3638908 | 2021-05-23T08:20:41.9161522Z | city: San Jose<br/>state: California<br/>countryOrRegion: US<br/>geoCoordinates: {"latitude": 37.33053, "longitude": -121.8382} | 86b6e4a1-25cb-40c7-af2b-9e79c6106000 | userPerformedSecuredPasswordChange | unfamiliarFeatures | low | remediated | unfamiliarFeatures | IdentityProtection | AzureAD |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | 2.2.2.2 | 2021-04-28T11:40:11.333738Z | signin | 2021-04-28T11:40:11.333738Z | [{"Key":"userAgent","Value":"python-requests/2.18.4"}] | 6f74b0f4-dabc-49af-aa87-3aaba042baba | realtime | c0e94938cddbb849ef64dbb6a98189ab3d93cdec4c4f95923ac935a91486def2 | 2021-05-23T08:20:29.027631Z | city: Frankfurt Am Main<br/>state: Hessen<br/>countryOrRegion: DE<br/>geoCoordinates: {"latitude": 50.1109, "longitude": 8.6821} | 64b01b65-25fa-4811-b4cd-411c9accc000 | userPerformedSecuredPasswordChange | unfamiliarFeatures | low | remediated | unfamiliarFeatures | IdentityProtection | AzureAD |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | 3.3.3.3 | 2021-04-29T08:03:23.5302796Z | signin | 2021-04-29T08:03:23.5302796Z | [{"Key":"userAgent","Value":"python-requests/2.18.4"}] | 069f7e67-3692-4191-a84d-14ab0aa1baba | realtime | c197aea67197503695f6dbddd9af2b3adcd1e8571f8381e96707ac71162d1cdf | 2021-05-23T08:20:42.1561664Z | city: Paris<br/>state: Paris<br/>countryOrRegion: FR<br/>geoCoordinates: {"latitude": 48.86023, "longitude": 2.34107} | 22e0bc21-61f2-4661-aa0b-afe40985e100 | userPerformedSecuredPasswordChange | unfamiliarFeatures | low | remediated | unfamiliarFeatures | IdentityProtection | AzureAD |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | 5.5.5.5 | 2021-05-07T06:00:45.0034244Z | signin | 2021-05-07T06:00:45.0034244Z | [{"Key":"userAgent","Value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"}] | dec7bb21-5a9b-45ff-84d6-b1538da801bc | realtime | 8b29fae724e168a32412e2bdc630540588df7558ac647772c36d957656b6e156 | 2021-05-23T08:20:42.2461705Z | city: Tanglin<br/>state: South West<br/>countryOrRegion: SG<br/>geoCoordinates: {"latitude": 1.32, "longitude": 103.8198} | 5fd28f4a-b172-4aa6-92b2-883832460400 | userPerformedSecuredPasswordChange | unfamiliarFeatures | low | remediated | unfamiliarFeatures | IdentityProtection | AzureAD |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | 4.4.4.4 | 2021-05-09T09:41:24.9769131Z | signin | 2021-05-09T09:41:24.9769131Z | [{"Key":"userAgent","Value":"BAV2ROPC"}] | f9dbd73b-8e7f-4bcd-93a7-2a7c1d4cbaba | realtime | dbc1272033adf3a2e960ce438a671de91b4b1b917e250ec575492156eb64f6eb | 2021-05-23T08:20:29.0726385Z | city: Stockholm<br/>state: Stockholms Lan<br/>countryOrRegion: SE<br/>geoCoordinates: {"latitude": 59.31512, "longitude": 18.05132} | d6e81927-c8e1-40f4-ad38-aa4d5408aa00 | userPerformedSecuredPasswordChange | unfamiliarFeatures | low | remediated | unfamiliarFeatures | IdentityProtection | AzureAD |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | 1.2.3.4 | 2021-05-11T07:15:33.6885155Z | signin | 2021-05-11T07:15:33.6885155Z | [{"Key":"userAgent","Value":"python-requests/2.25.1"}] | 5bb85e1f-1933-4698-831d-fbeb40aebaba | realtime | 969476f4d6d20717dfaea9f2df92945f9d736240d53b4187b50579003bf2d011 | 2021-05-23T08:20:42.2911741Z | city: Dublin<br/>state: Dublin<br/>countryOrRegion: IE<br/>geoCoordinates: {"latitude": 53.35389, "longitude": -6.24333} | 7b7d098c-edcc-4139-b171-fc64c38d0d00 | userPerformedSecuredPasswordChange | unfamiliarFeatures | low | remediated | unfamiliarFeatures | IdentityProtection | AzureAD |


### azure-ad-identity-protection-risky-user-list
***
Retrieves the properties of a collection of riskDetection objects.

#### Required Permissions
`IdentityRiskEvent.Read.All`

#### Base Command

`azure-ad-identity-protection-risky-user-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| updated_time | The time elapsed since the risky user was last updated, formatted as `<number> <time unit>`, e.g., `12 hours` or `7 days`. | Optional | 
| risk_level | Risk level of the detected risky user. The possible values are low, medium, high, hidden, none, and unknownFeatureValue. | Optional | 
| risk_state | State of the user's risk. The possible values are none, confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised, and unknownFutureValue. | Optional | 
| risk_detail | Details of the detected risk. The possible values are none, adminGeneratedTemporaryPassword, userPerformedSecuredPasswordChange, userPerformedSecuredPasswordReset, adminConfirmedSigninSafe, aiConfirmedSigninSafe, userPassedMFADrivenByRiskBasedPolicy, adminDismissedAllRiskForUser, adminConfirmedSigninCompromised, hidden, adminConfirmedUserCompromised, and unknownFutureValue. | Optional | 
| filter_expression | A custom query in OData syntax. Using this overrides all arguments, except for next_link. For more details, see https://docs.microsoft.com/en-us/graph/query-parameters. | Optional | 
| limit | Number of results to provide. Default is 50. | Optional | 
| next_link | A link that specifies a starting point for subsequent calls. Using this argument overrides all other arguments. | Optional | 
| user_name | Risky user principal name. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AADIdentityProtection.RiskyUsers.id | string | Unique ID of the risky user. | 
| AADIdentityProtection.RiskyUsers.isDeleted | Boolean | Indicates whether the user is deleted. | 
| AADIdentityProtection.RiskyUsers.isProcessing | Boolean | Indicates whether a user's risky state is being processed by the backend. | 
| AADIdentityProtection.RiskyUsers.riskLastUpdatedDateTime | DateTime | The date and time that the risky user was last updated. The DateTimeOffset type represents date and time information using the ISO 8601 format and is always in UTC time. | 
| AADIdentityProtection.RiskyUsers.riskLevel | string | Risk level of the detected risky user. The possible values are low, medium, high, hidden, none, and unknownFutureValue. | 
| AADIdentityProtection.RiskyUsers.riskState | string | State of the user's risk. The possible values are none, confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised, and unknownFutureValue. | 
| AADIdentityProtection.RiskyUsers.riskDetail | string | Reason why the user is considered a risky user. The possible values are limited to none, adminGeneratedTemporaryPassword, userPerformedSecuredPasswordChange, userPerformedSecuredPasswordReset, adminConfirmedSigninSafe, aiConfirmedSigninSafe, userPassedMFADrivenByRiskBasedPolicy, adminDismissedAllRiskForUser, adminConfirmedSigninCompromised, hidden, adminConfirmedUserCompromised, and unknownFutureValue. | 
| AADIdentityProtection.RiskyUsers.userDisplayName | string | Risky user display name. | 
| AADIdentityProtection.RiskyUsers.userPrincipalName | string | Risky user principal name. | 


#### Command Example
```!azure-ad-identity-protection-risky-user-list```

#### Context Example
```json
{
    "AADIdentityProtection": {
        "RiskyUsers": [
          {
                "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                "isDeleted": false,
                "isProcessing": false,
                "riskDetail": "none",
                "riskLastUpdatedDateTime": "2021-07-21T17:56:28.958147Z",
                "riskLevel": "medium",
                "riskState": "atRisk",
                "userDisplayName": "John Doe",
                "userPrincipalName": "jdoe@example.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Risky Users (1 result)
>|User Principal Name|User Display Name|ID|Is Deleted|Is Processing|Risk Detail|Risk Last Updated Date Time|Risk Level|Risk State|
>|---|---|---|---|---|---|---|---|---|
>| jdoe@example.com | John Doe | 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | false | false | none | 2021-07-21T17:56:28.958147Z | medium | atRisk |


### azure-ad-identity-protection-risky-user-history-list
***
Gets the risk history of a riskyUser resource.

#### Required Permissions
`IdentityRiskyUser.Read.All`
`IdentityRiskyUser.ReadWrite.All`

#### Base Command

`azure-ad-identity-protection-risky-user-history-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | Unique ID of the user. | Required | 
| limit | Number of results to provide. Default is 50. | Optional | 
| filter_expression | A custom query in OData syntax. Using this overrides all arguments, except for next_link. For more details, see https://docs.microsoft.com/en-us/graph/query-parameters. | Optional | 
| next_link | A link that specifies a starting point for subsequent calls. Using this argument overrides all other arguments. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AADIdentityProtection.RiskyUserHistory.id | string | Unique ID of the risky user. | 
| AADIdentityProtection.RiskyUserHistory.isDeleted | Boolean | Indicates whether the user is deleted. | 
| AADIdentityProtection.RiskyUserHistory.isProcessing | Boolean | Indicates whether a user's risky state is being processed by the backend. | 
| AADIdentityProtection.RiskyUserHistory.riskLastUpdatedDateTime | DateTime | The date and time that the risky user was last updated. The DateTimeOffset type represents date and time information using the ISO 8601 format and is always in UTC time. | 
| AADIdentityProtection.RiskyUserHistory.riskLevel | string | Risk level of the detected risky user. The possible values are low, medium, high, hidden, none, and unknownFutureValue. | 
| AADIdentityProtection.RiskyUserHistory.riskState | string | State of the user's risk. The possible values are none, confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised, and unknownFutureValue. | 
| AADIdentityProtection.RiskyUserHistory.riskDetail | string | Reason why the user is considered a risky user. The possible values are limited to none, adminGeneratedTemporaryPassword, userPerformedSecuredPasswordChange, userPerformedSecuredPasswordReset, adminConfirmedSigninSafe, aiConfirmedSigninSafe, userPassedMFADrivenByRiskBasedPolicy, adminDismissedAllRiskForUser, adminConfirmedSigninCompromised, hidden, adminConfirmedUserCompromised, and unknownFutureValue. | 
| AADIdentityProtection.RiskyUserHistory.userDisplayName | string | Risky user display name. | 
| AADIdentityProtection.RiskyUserHistory.userPrincipalName | string | Risky user principal name. | 


#### Command Example
```!azure-ad-identity-protection-risky-user-history-list user_id="3fa9f28b-eb0e-463a-ba7b-8089fe9991e2"```

#### Context Example
```json
{
    "AADIdentityProtection": {
        "RiskyUserHistory": [
            {
                "activity": {
                    "detail": null,
                    "eventTypes": [
                        "unfamiliarFeatures"
                    ],
                    "riskEventTypes": [
                        "unfamiliarFeatures"
                    ]
                },
                "id": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2637571860258849619",
                "initiatedBy": null,
                "isDeleted": false,
                "isProcessing": false,
                "riskDetail": "none",
                "riskLastUpdatedDateTime": "2021-05-21T09:27:05.8849619Z",
                "riskLevel": "high",
                "riskState": "atRisk",
                "userDisplayName": "John Doe",
                "userId": "3fa9f28b-eb0e-463a-ba7b-8089fe9991e2",
                "userPrincipalName": "jdoe@example.com"
            }
        ]
    }
}
```

#### Human Readable Output

>### Risky User History For 3Fa9F28B-Eb0E-463A-Ba7B-8089Fe9991E2 (12 results)
>|User ID|User Principal Name|User Display Name|Activity|ID|Initiated By|Is Deleted|Is Processing|Risk Detail|Risk Last Updated Date Time|Risk Level|Risk State|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | eventTypes: unfamiliarFeatures<br/>riskEventTypes: unfamiliarFeatures<br/>detail: null | 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2637571860258849619 |  | false | false | none | 2021-05-21T09:27:05.8849619Z | high | atRisk |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | eventTypes: unfamiliarFeatures<br/>riskEventTypes: unfamiliarFeatures<br/>detail: null | 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2637579558855706894 |  | false | false | none | 2021-05-30T07:18:05.5706894Z | low | atRisk |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | eventTypes: unfamiliarFeatures<br/>riskEventTypes: unfamiliarFeatures<br/>detail: null | 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2637581817194185440 |  | false | false | none | 2021-06-01T22:01:59.418544Z | low | atRisk |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | eventTypes: unfamiliarFeatures<br/>riskEventTypes: unfamiliarFeatures<br/>detail: null | 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2637617844902084332 |  | false | false | none | 2021-07-13T14:48:10.2084332Z | low | atRisk |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | eventTypes: unfamiliarFeatures,<br/>mcasImpossibleTravel<br/>riskEventTypes: unfamiliarFeatures,<br/>mcasImpossibleTravel<br/>detail: null | 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2637617905007494900 |  | false | false | none | 2021-07-13T16:28:20.74949Z | medium | atRisk |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | eventTypes: unfamiliarFeatures<br/>riskEventTypes: unfamiliarFeatures<br/>detail: null | 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 |  | false | false | none | 2021-07-21T17:56:28.958147Z | medium | atRisk |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | eventTypes: <br/>riskEventTypes: <br/>detail: userPerformedSecuredPasswordChange | 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2637573546620000000 |  | false | false | userPerformedSecuredPasswordChange | 2021-05-23T08:17:42Z | none | remediated |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | eventTypes: mcasImpossibleTravel<br/>riskEventTypes: mcasImpossibleTravel<br/>detail: null | 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2637580439207803793 |  | false | false | none | 2021-05-31T07:45:20.7803793Z | low | atRisk |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | eventTypes: unfamiliarFeatures<br/>riskEventTypes: unfamiliarFeatures<br/>detail: null | 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2637588246283692301 |  | false | false | none | 2021-06-09T08:37:08.3692301Z | low | atRisk |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | eventTypes: mcasImpossibleTravel<br/>riskEventTypes: mcasImpossibleTravel<br/>detail: null | 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2637597636382264783 |  | false | false | none | 2021-06-20T05:27:18.2264783Z | low | atRisk |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | eventTypes: unfamiliarFeatures<br/>riskEventTypes: unfamiliarFeatures<br/>detail: null | 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2637600753627454017 |  | false | false | none | 2021-06-23T20:02:42.7454017Z | low | atRisk |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | eventTypes: <br/>riskEventTypes: <br/>detail: adminDismissedAllRiskForUser | 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2637623861161706539 | 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | false | false | adminDismissedAllRiskForUser | 2021-07-20T13:55:16.1706539Z | none | dismissed |


### azure-ad-identity-protection-risky-user-confirm-compromised
***
Confirms one or more riskyUser objects as compromised. This action sets the targeted user's risk level to high.

#### Required Permissions
`IdentityRiskyUser.ReadWrite.All`

#### Base Command

`azure-ad-identity-protection-risky-user-confirm-compromised`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_ids | One or more user IDs, comma-separated. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-ad-identity-protection-risky-user-confirm-compromised user_ids="3fa9f28b-eb0e-463a-ba7b-8089fe9991e3"```

#### Human Readable Output

>✅ Confirmed successfully.

### azure-ad-identity-protection-risky-user-dismiss
***
Dismisses the risk of one or more riskyUser objects. This action sets the targeted user's risk level to none.

#### Required Permissions
`IdentityRiskyUser.ReadWrite.All`

#### Base Command

`azure-ad-identity-protection-risky-user-dismiss`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_ids | One or more user IDs, comma-separated. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
```!azure-ad-identity-protection-risky-user-dismiss user_ids="3fa9f28b-eb0e-463a-ba7b-8089fe9991e2"```

#### Human Readable Output

>✅ Dismissed successfully.
