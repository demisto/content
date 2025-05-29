Use the Azure Active Directory Identity And Access integration to manage roles and members.

## Configure Azure Active Directory Identity and Access in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Application ID | False |
| Private Key | False |
| Certificate Thumbprint | False |
| Use Azure Managed Identities | False |
| Azure Managed Identities Client ID | False |
| Azure AD endpoint | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

## Required Permissions

To use this integration, the following permissions are required on the Azure app.  

- `IdentityRiskEvent.Read.All`
- `IdentityRiskyUser.ReadWrite.All`
- `RoleManagement.ReadWrite.Directory`
- `Policy.ReadWrite.ConditionalAccess`
- `Policy.Read.All`

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### msgraph-identity-auth-start

***
Run this command to start the authorization process and follow the instructions in the command results.

### msgraph-identity-auth-complete

***
Run this command to complete the authorization process.
Should be used after running the msgraph-identity-auth-start command.

### msgraph-identity-auth-reset

***
Run this command if for some reason you need to rerun the authentication process.

### msgraph-identity-auth-test

***
Tests connectivity to Microsoft.

### msgraph-identity-directory-roles-list

***
Lists the roles in the directory.

#### Base Command

`msgraph-identity-directory-roles-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| limit | Maximum number of results to fetch. Default is 10. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphIdentity.Role.deletedDateTime | Date | The time when a role was deleted. Displays only if a role was deleted. |
| MSGraphIdentity.Role.description | String | The description of the directory role. |
| MSGraphIdentity.Role.displayName | String | The display name of the directory role. |
| MSGraphIdentity.Role.id | String | The unique identifier of the directory role. |
| MSGraphIdentity.Role.roleTemplateId | String | The ID of the directory role template on which the role is based. |

#### Command Example

```!msgraph-identity-directory-roles-list limit=1```

#### Context Example

```json
{
    "MSGraphIdentity": {
        "Role": {
            "deletedDateTime": null,
            "description": "Can create and manage all aspects of app registrations and enterprise apps.",
            "displayName": "Application Administrator",
            "id": ":id:",
            "roleTemplateId": "role-template-id"
        }
    }
}
```

#### Human Readable Output

>### Directory roles
>
>|id|displayName|description|roleTemplateId|
>|---|---|---|---|
>| id | Application Administrator | Can create and manage all aspects of app registrations and enterprise apps. | role-template-id |

### msgraph-identity-directory-role-activate

***
Activates a role by its template ID.

#### Base Command

`msgraph-identity-directory-role-activate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_template_id | ID of the role template to activate. Can be retrieved using the msgraph-identity-directory-roles-list command. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphIdentity.Role.deletedDateTime | Date | The time when the role was deleted. Displays only if the role was deleted. |
| MSGraphIdentity.Role.description | String | The description of the directory role. |
| MSGraphIdentity.Role.displayName | String | The display name of the directory role. |
| MSGraphIdentity.Role.id | String | The unique identifier of the directory role. |
| MSGraphIdentity.Role.roleTemplateId | String | The ID of the directory role template on which this role is based. |

#### Command Example

```!msgraph-identity-directory-role-activate role_template_id=role-template-id```

#### Context Example

```json
{
    "MSGraphIdentity": {
        "Role": {
            "deletedDateTime": null,
            "description": "Can create and manage all aspects of app registrations and enterprise apps.",
            "displayName": "Application Administrator",
            "id": ":id:",
            "roleTemplateId": "role-template-id"
        }
    }
}
```

#### Human Readable Output

>### Role has been activated
>
>|id|roleTemplateId|displayName|description|deletedDateTime|
>|---|---|---|---|---|
>| id | role-template-id | Application Administrator | Can create and manage all aspects of app registrations and enterprise apps. |  |

### msgraph-identity-directory-role-members-list

***
Gets all members in a role ID.

#### Base Command

`msgraph-identity-directory-role-members-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_id | The ID of the application for which to get its role members list. Can be retrieved using the msgraph-identity-directory-roles-list command. | Required |
| limit | The maximum number of members to fetch. Default is 10. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphIdentity.RoleMember.user_id | String | The unique identifier of the user in the role. |
| MSGraphIdentity.RoleMember.role_id | String | The unique identifier of the role specified in the input. |

#### Command Example

```!msgraph-identity-directory-role-members-list role_id=:role:```

#### Context Example

```json
{
    "MSGraphIdentity": {
        "RoleMember": {
            "role_id": ":role:",
            "user_id": [
                "70585180-517a-43ea-9403-2d80b97ab19d",
                "5d9ed8e5-be5c-4aaf-86f8-c133c5cd19de"
            ]
        }
    }
}
```

#### Human Readable Output

>### Role ':role:' members
>
>|role_id|user_id|
>|---|---|
>| :role: | 70585180-517a-43ea-9403-2d80b97ab19d,<br/>5d9ed8e5-be5c-4aaf-86f8-c133c5cd19de,<br/>"id",<br/>a7cedb37-c4e5-4cfb-a327-7bafb34a1f49 |

### msgraph-identity-directory-role-member-add

***
Adds a user to a role.

#### Base Command

`msgraph-identity-directory-role-member-add`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_id | The ID of the role to add the user to. Can be retrieved using the msgraph-identity-directory-roles-list command. | Required |
| user_id | The ID of the user to add to the role. Can be retrieved using the msgraph-identity-directory-role-members-list command. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!msgraph-identity-directory-role-member-add role_id=:role: user_id=:id:```

#### Human Readable Output

>User ID :id: has been added to role :role:

### msgraph-identity-directory-role-member-remove

***
Removes a user from a role.

#### Base Command

`msgraph-identity-directory-role-member-remove`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role_id | ID of the role from which to remove the user. Can be retrieved using the msgraph-identity-directory-roles-list command. | Required |
| user_id | ID of the user to remove from the role. Can be retrieved using the msgraph-identity-directory-role-members-list command. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!msgraph-identity-directory-role-member-remove role_id=:role: user_id=:id:```

#### Human Readable Output

>User ID :id: has been removed from role :role:

### msgraph-identity-ip-named-locations-create

***
Creates an ip named location.

#### Base Command

`msgraph-identity-ip-named-locations-create`

#### Input

| **Argument Name** | **Description**                                        | **Required** |
|-------------------|--------------------------------------------------------| --- |
| display_name      | The display name for the ip named location.            | Required |
| is_trusted        | A boolean to show if the ip named location is trusted. | Required |
| ips               | The ip ranges for the ip named location.               | Required |

#### Context Output

| **Path**                                                    | **Type** | **Description** |  
|-------------------------------------------------------------| --- | --- |
| MSGraph.conditionalAccess.namedIpLocations.time_created     | Date | The time of the ip named location creation. |
| MSGraph.conditionalAccess.namedIpLocations.time_modified    | Date | The time the ip named location was last modified. |
| MSGraph.conditionalAccess.namedIpLocations.display_name     | String | The ip named location display name. |
| MSGraph.conditionalAccess.namedIpLocations.id               | String | The unique identifier of the ip named location. |
| MSGraph.conditionalAccess.namedIpLocations.is_trusted       | String | The ip named location trust status. |
| MSGraph.conditionalAccess.namedIpLocations.ip_ranges        | Array | The ip named location ip ranges. |

#### Command Example

```!msgraph-identity-ip-named-locations-create ips=12.34.221.11/22,2001:0:9d38:90d6:0:0:0:0/63 display_name=test is_trusted=True:```

#### Human Readable Output

>created Ip named location 'ID': :ipNamedLocation:  

### msgraph-identity-ip-named-locations-get

***
Gets an ip named location.

#### Base Command

`msgraph-identity-ip-named-locations-get`

#### Input

| **Argument Name** | **Description**                         | **Required** |
|-------------------|-----------------------------------------| --- |
| ip_id             | The id of the ip named location to get. | Required |

#### Context Output

| **Path**                                                 | **Type** | **Description** |
|----------------------------------------------------------| --- | --- |
| MSGraph.conditionalAccess.namedIpLocations.time_created  | Date | The time of the ip named location creation. |
| MSGraph.conditionalAccess.namedIpLocations.time_modified | Date | The time the ip named location was last modified. |
| MSGraph.conditionalAccess.namedIpLocations.display_name  | String | The ip named location display name. |
| MSGraph.conditionalAccess.namedIpLocations.id            | String | The unique identifier of the ip named location. |
| MSGraph.conditionalAccess.namedIpLocations.is_trusted    | String | The ip named location trust status. |
| MSGraph.conditionalAccess.namedIpLocations.ip_ranges     | Array | The ip named location ip ranges. |

#### Command Example

```!msgraph-identity-ip-named-locations-get ip_id=03f8c56f-2ffd-4699-84af-XXXXXXXCX```

#### Human Readable Output

>Ip named location 'ID': :ipNamedLocation:

### msgraph-identity-ip-named-locations-delete

***
Deletes an ip named location.

#### Base Command

`msgraph-identity-ip-named-locations-delete`

#### Input

| **Argument Name** | **Description**                            | **Required** |
|-------------------|--------------------------------------------| --- |
| ip_id             | The id of the ip named location to delete. | Required |

#### Context Output

No context output

#### Command Example

```!msgraph-identity-ip-named-locations-delete ip_id=03f8c56f-2ffd-4699-84af-XXXXXXXCX```

#### Human Readable Output

>Successfully deleted IP named location 'X-X-X-X'

### msgraph-identity-ip-named-locations-update

***
Updates an ip named location.

#### Base Command

`msgraph-identity-ip-named-locations-update`

#### Input

| **Argument Name** | **Description**                                        | **Required** |
|-------------------|--------------------------------------------------------| --- |
| ip_id             | The id of the ip named location to delete.             | Required |
| display_name      | The display name for the ip named location.            | Required |
| is_trusted        | A boolean to show if the ip named location is trusted. | Required |
| ips               | The ip ranges for the ip named location.               | Required |

#### Context Output

No context output

#### Command Example

```!msgraph-identity-ip-named-locations-update ips=12.34.221.11/22,2001:0:9d38:90d6:0:0:0:0/63 display_name=test is_trusted=True ip_id=098699fc-10ad-420e-9XXXXXXXXXX```

#### Human Readable Output

>Successfully updated IP named location '006cc9bf-8391-4ff3-8cff-ee87f06b7b02'

### msgraph-identity-ip-named-locations-list

***
Lists an ip named locations.

#### Base Command

`msgraph-identity-ip-named-locations-list`

#### Input

| **Argument Name** | **Description**                | **Required** |
|-------------------|--------------------------------|--------------|
| limit             | The get request results limit. | Optional     |
| page              | The page to get the data from. | Optional     |
| odata_query       | An odata query to send to the api. | Optional     |

#### Context Output

| **Path**                                                      | **Type** | **Description** |
|---------------------------------------------------------------| --- | --- |
| MSGraph.conditionalAccess.namedIpLocations.ip_named_locations | Array | List of ip named locations. |

#### Command Example

```!msgraph-identity-ip-named-locations-list```

### msgraph-identity-protection-risks-list

***
Retrieve the properties of a collection of riskDetection objects.

#### Required Permissions

`IdentityRiskEvent.Read.All`

#### Base Command

`msgraph-identity-protection-risks-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| odata_query | An odata query to send to the api. | Optional     |
| limit | Number of results to provide. Default is 50. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraph.identityProtection.risks.id | string | Unique ID of the risk detection. |
| MSGraph.identityProtection.risks.requestId | string | The ID of the sign-in associated with the risk detection. This property is null if the risk detection is not associated with a sign-in. |
| MSGraph.identityProtection.risks.correlationId | string | Correlation ID of the sign-in associated with the risk detection. This property is null if the risk detection is not associated with a sign-in. |
| MSGraph.identityProtection.risks.riskEventType | string | The type of risk event detected. The possible values are unlikelyTravel, anonymizedIPAddress, maliciousIPAddress, unfamiliarFeatures, malwareInfectedIPAddress, suspiciousIPAddress, leakedCredentials, investigationsThreatIntelligence, generic,adminConfirmedUserCompromised, mcasImpossibleTravel, mcasSuspiciousInboxManipulationRules, investigationsThreatIntelligenceSigninLinked, maliciousIPAddressValidCredentialsBlockedIP, and unknownFutureValue. |
| MSGraph.identityProtection.risks.riskType | string | Deprecated. Use riskEventType instead. List of risk event types. |
| MSGraph.identityProtection.risks.riskLevel | string | Risk level of the detected risky user. The possible values are low, medium, high, hidden, none, and unknownFutureValue. |
| MSGraph.identityProtection.risks.riskstate | string | State of the user's risk. The possible values are none, confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised, and unknownFutureValue. |
| MSGraph.identityProtection.risks.riskDetail | string | Reason why the user is considered a risky user. The possible values are limited to none, adminGeneratedTemporaryPassword, userPerformedSecuredPasswordChange, userPerformedSecuredPasswordReset, adminConfirmedSigninSafe, aiConfirmedSigninSafe, userPassedMFADrivenByRiskBasedPolicy, adminDismissedAllRiskForUser, adminConfirmedSigninCompromised, hidden, adminConfirmedUserCompromised, and unknownFutureValue. |
| MSGraph.identityProtection.risks.source | string | Source of the risk detection. For example, `activeDirectory`. |
| MSGraph.identityProtection.risks.detectionTimingType | string | Timing of the detected risk \(real-time/offline\). The possible values are notDefined, realtime, nearRealtime, offline, and unknownFutureValue. |
| MSGraph.identityProtection.risks.activity | string | Indicates the activity type the detected risk is linked to. The possible values are signin, user, and unknownFutureValue. |
| MSGraph.identityProtection.risks.tokenIssuerType | string | Indicates the type of token issuer for the detected sign-in risk. The possible values are AzureAD, ADFederationServices, and unknownFutureValue. |
| MSGraph.identityProtection.risks.ipAddress | string | Provides the IP address of the client from where the risk occurred. |
| MSGraph.identityProtection.risks.location.city | string | City of the sign-in. |
| MSGraph.identityProtection.risks.location.countryOrRegion | string | Country or region of the sign-in. |
| MSGraph.identityProtection.risks.location.geoCoordinates.latitude | string | Latitude of the sign-in. |
| MSGraph.identityProtection.risks.location.geoCoordinates.longitude | string | Longitude of the sign-in. |
| MSGraph.identityProtection.risks.location.state | string | State of the sign-in. |
| MSGraph.identityProtection.risks.activityDateTime | string | Date and time that the risky activity occurred. The DateTimeOffset type represents date and time information using the ISO 8601 format and is always in UTC time. |
| MSGraph.identityProtection.risks.detectedDateTime | string | Date and time that the risk was detected. The DateTimeOffset type represents date and time information using the ISO 8601 format and is always in UTC time. |
| MSGraph.identityProtection.risks.lastUpdatedDateTime | string | Date and time that the risk detection was last updated. The DateTimeOffset type represents date and time information using the ISO 8601 format and is always in UTC time. |
| MSGraph.identityProtection.risks.userId | string | Unique ID of the user. |
| MSGraph.identityProtection.risks.userDisplayName | string | Risky user display name. |
| MSGraph.identityProtection.risks.userPrincipalName | string | Risky user principal name. |
| MSGraph.identityProtection.risks.additionalInfo | string | Additional information associated with the risk detection in JSON format. |

#### Command Example

```!msgraph-identity-protection-risks-list```

#### Human Readable Output

>### risks (6 results)
>
>|User ID|User Principal Name|User Display Name|IP Address|Detected Date Time|Activity|Activity Date Time|Additional Info|Correlation ID|Detection Timing Type|ID|Last Updated Date Time|Location|Request ID|Risk Detail|Risk Event Type|Risk Level|Risk State|Risk Type|Source|Token Issuer Type|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | 1.1.1.1 | 2021-04-25T09:00:40.7780969Z | signin | 2021-04-25T09:00:40.7780969Z | [{"Key":"userAgent","Value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36"}] | 271ac223-695b-418e-85b3-7809070ee33e | realtime | 86a45315157fb75c3a6e0936ef854c139df99bdfbde4bd7e7f1bc685c3638908 | 2021-05-23T08:20:41.9161522Z | city: San Jose<br/>state: California<br/>countryOrRegion: US<br/>geoCoordinates: {"latitude": 37.33053, "longitude": -121.8382} | 86b6e4a1-25cb-40c7-af2b-9e79c6106000 | userPerformedSecuredPasswordChange | unfamiliarFeatures | low | remediated | unfamiliarFeatures | IdentityProtection | AzureAD |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | 2.2.2.2 | 2021-04-28T11:40:11.333738Z | signin | 2021-04-28T11:40:11.333738Z | [{"Key":"userAgent","Value":"python-requests/2.18.4"}] | 6f74b0f4-dabc-49af-aa87-3aaba042baba | realtime | c0e94938cddbb849ef64dbb6a98189ab3d93cdec4c4f95923ac935a91486def2 | 2021-05-23T08:20:29.027631Z | city: Frankfurt Am Main<br/>state: Hessen<br/>countryOrRegion: DE<br/>geoCoordinates: {"latitude": 50.1109, "longitude": 8.6821} | 64b01b65-25fa-4811-b4cd-411c9accc000 | userPerformedSecuredPasswordChange | unfamiliarFeatures | low | remediated | unfamiliarFeatures | IdentityProtection | AzureAD |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | 3.3.3.3 | 2021-04-29T08:03:23.5302796Z | signin | 2021-04-29T08:03:23.5302796Z | [{"Key":"userAgent","Value":"python-requests/2.18.4"}] | 069f7e67-3692-4191-a84d-14ab0aa1baba | realtime | c197aea67197503695f6dbddd9af2b3adcd1e8571f8381e96707ac71162d1cdf | 2021-05-23T08:20:42.1561664Z | city: Paris<br/>state: Paris<br/>countryOrRegion: FR<br/>geoCoordinates: {"latitude": 48.86023, "longitude": 2.34107} | 22e0bc21-61f2-4661-aa0b-afe40985e100 | userPerformedSecuredPasswordChange | unfamiliarFeatures | low | remediated | unfamiliarFeatures | IdentityProtection | AzureAD |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | 5.5.5.5 | 2021-05-07T06:00:45.0034244Z | signin | 2021-05-07T06:00:45.0034244Z | [{"Key":"userAgent","Value":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36"}] | dec7bb21-5a9b-45ff-84d6-b1538da801bc | realtime | 8b29fae724e168a32412e2bdc630540588df7558ac647772c36d957656b6e156 | 2021-05-23T08:20:42.2461705Z | city: Tanglin<br/>state: South West<br/>countryOrRegion: SG<br/>geoCoordinates: {"latitude": 1.32, "longitude": 103.8198} | 5fd28f4a-b172-4aa6-92b2-883832460400 | userPerformedSecuredPasswordChange | unfamiliarFeatures | low | remediated | unfamiliarFeatures | IdentityProtection | AzureAD |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | 4.4.4.4 | 2021-05-09T09:41:24.9769131Z | signin | 2021-05-09T09:41:24.9769131Z | [{"Key":"userAgent","Value":"BAV2ROPC"}] | f9dbd73b-8e7f-4bcd-93a7-2a7c1d4cbaba | realtime | dbc1272033adf3a2e960ce438a671de91b4b1b917e250ec575492156eb64f6eb | 2021-05-23T08:20:29.0726385Z | city: Stockholm<br/>state: Stockholms Lan<br/>countryOrRegion: SE<br/>geoCoordinates: {"latitude": 59.31512, "longitude": 18.05132} | d6e81927-c8e1-40f4-ad38-aa4d5408aa00 | userPerformedSecuredPasswordChange | unfamiliarFeatures | low | remediated | unfamiliarFeatures | IdentityProtection | AzureAD |
>| 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | jdoe@example.com | John Doe | 1.2.3.4 | 2021-05-11T07:15:33.6885155Z | signin | 2021-05-11T07:15:33.6885155Z | [{"Key":"userAgent","Value":"python-requests/2.25.1"}] | 5bb85e1f-1933-4698-831d-fbeb40aebaba | realtime | 969476f4d6d20717dfaea9f2df92945f9d736240d53b4187b50579003bf2d011 | 2021-05-23T08:20:42.2911741Z | city: Dublin<br/>state: Dublin<br/>countryOrRegion: IE<br/>geoCoordinates: {"latitude": 53.35389, "longitude": -6.24333} | 7b7d098c-edcc-4139-b171-fc64c38d0d00 | userPerformedSecuredPasswordChange | unfamiliarFeatures | low | remediated | unfamiliarFeatures | IdentityProtection | AzureAD |

### msgraph-identity-protection-risky-user-list

***
Retrieves the properties of a collection of riskDetection objects.

#### Required Permissions

`IdentityRiskEvent.Read.All`

#### Base Command

`msgraph-identity-protection-risky-user-list`

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

| **Path** | **Type** | **Description**                                                                                                                                                                                                                                                                                                                                                                                         |
| --- | --- |---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| MSGraph.identityProtection.risky-users.id | string | Unique ID of the risky user.                                                                                                                                                                                                                                                                                                                                                                            |
| MSGraph.identityProtection.risky-users.isDeleted | Boolean | Indicates whether a user is delted                                                                                                                                                                                                                                                                                                                                                                      |
| MSGraph.identityProtection.risky-users.isProcessing | Boolean | Indicates whether a user's risky state is being processed by the backend.                                                                                                                                                                                                                                                                                                                               |
| MSGraph.identityProtection.risky-users.riskLastUpdatedDateTime | DateTime | The date and time that the risky user was last updated. The DateTimeOffset type represents date and time information using the ISO 8601 format and is always in UTC time.                                                                                                                                                                                                                               |
| MSGraph.identityProtection.risky-users.riskLevel | string | Risk level of the detected risky user. The possible values are low, medium, high, hidden, none, and unknownFutureValue.                                                                                                                                                                                                                                                                                 |
| MSGraph.identityProtection.risky-users.riskstate | string | State of the user's risk. The possible values are none, confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised, and unknownFutureValue.                                                                                                                                                                                                                                                     |
| MSGraph.identityProtection.risky-users.riskDetail | string | Reason why the user is considered a risky user. The possible values are limited to none, adminGeneratedTemporaryPassword, userPerformedSecuredPasswordChange, userPerformedSecuredPasswordReset, adminConfirmedSigninSafe, aiConfirmedSigninSafe, userPassedMFADrivenByRiskBasedPolicy, adminDismissedAllRiskForUser, adminConfirmedSigninCompromised, hidden, adminConfirmedUserCompromised, and unknownFutureValue. |
| MSGraph.identityProtection.risky-users.userDisplayName | string | Risky user display name.                                                                                                                                                                                                                                                                                                                                                                                |
| MSGraph.identityProtection.risky-users.userPrincipalName | string | Risky user principal name.                                                                                                                                                                                                                                                                                                                                                                              |

#### Command Example

```!msgraph-identity-protection-risky-user-list```

#### Human Readable Output

>### Risky Users (1 result)
>
>|User Principal Name|User Display Name|ID|Is Deleted|Is Processing|Risk Detail|Risk Last Updated Date Time|Risk Level|Risk State|
>|---|---|---|---|---|---|---|---|---|
>| jdoe@example.com | John Doe | 3fa9f28b-eb0e-463a-ba7b-8089fe9991e2 | false | false | none | 2021-07-21T17:56:28.958147Z | medium | atRisk |

### msgraph-identity-protection-risky-user-history-list

***
Gets the risk history of a riskyUser resource.

#### Required Permissions

`IdentityRiskyUser.Read.All`
`IdentityRiskyUser.ReadWrite.All`

#### Base Command

`msgraph-identity-protection-risky-user-history-list`

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
| MSGraph.identityProtection.RiskyUserHistory.id | string | Unique ID of the risky user. |
| MSGraph.identityProtection.RiskyUserHistory.isDeleted | Boolean | Indicates whether the user is deleted. |
| MSGraph.identityProtection.RiskyUserHistory.isProcessing | Boolean | Indicates whether a user's risky state is being processed by the backend. |
| MSGraph.identityProtection.RiskyUserHistory.riskLastUpdatedDateTime | DateTime | The date and time that the risky user was last updated. The DateTimeOffset type represents date and time information using the ISO 8601 format and is always in UTC time. |
| MSGraph.identityProtection.RiskyUserHistory.riskLevel | string | Risk level of the detected risky user. The possible values are low, medium, high, hidden, none, and unknownFutureValue. |
| MSGraph.identityProtection.RiskyUserHistory.riskstate | string | State of the user's risk. The possible values are none, confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised, and unknownFutureValue. |
| MSGraph.identityProtection.RiskyUserHistory.riskDetail | string | Reason why the user is considered a risky user. The possible values are limited to none, adminGeneratedTemporaryPassword, userPerformedSecuredPasswordChange, userPerformedSecuredPasswordReset, adminConfirmedSigninSafe, aiConfirmedSigninSafe, userPassedMFADrivenByRiskBasedPolicy, adminDismissedAllRiskForUser, adminConfirmedSigninCompromised, hidden, adminConfirmedUserCompromised, and unknownFutureValue. |
| MSGraph.identityProtection.RiskyUserHistory.userDisplayName | string | Risky user display name. |
| MSGraph.identityProtection.RiskyUserHistory.userPrincipalName | string | Risky user principal name. |

#### Command Example

```!msgraph-identity-protection-risky-user-history-list user_id="3fa9f28b-eb0e-463a-ba7b-8089fe9991e2"```

#### Human Readable Output

>### Risky User History For 3Fa9F28B-Eb0E-463A-Ba7B-8089Fe9991E2 (12 results)
>
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

### msgraph-identity-protection-risky-user-confirm-compromised

***
Confirms one or more riskyUser objects as compromised. This action sets the targeted user's risk level to high.

#### Required Permissions

`IdentityRiskyUser.ReadWrite.All`

#### Base Command

`msgraph-identity-protection-risky-user-confirm-compromised`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_ids | One or more user IDs, comma-separated. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!MSGraph.identityProtection-risky-user-confirm-compromised user_ids="3fa9f28b-eb0e-463a-ba7b-8089fe9991e3"```

#### Human Readable Output

>✅ Confirmed successfully.

### msgraph-identity-protection-risky-user-dismiss

***
Dismisses the risk of one or more riskyUser objects. This action sets the targeted user's risk level to none.

#### Required Permissions

`IdentityRiskyUser.ReadWrite.All`

#### Base Command

`msgraph-identity-protection-risky-user-dismiss`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_ids | One or more user IDs, comma-separated. | Required |

#### Context Output

There is no context output for this command.

#### Command Example

```!c user_ids="3fa9f28b-eb0e-463a-ba7b-8089fe9991e2"```

#### Human Readable Output

>✅ Dismissed successfully.
### msgraph-identity-ca-policy-create

***
Creates a Conditional Access policy.

#### Base Command

`msgraph-identity-ca-policy-create`

#### Required Permissions

`Permission type : Application or Delegated`
`Permissions:Policy.Read.All`
`Policy.ReadWrite.ConditionalAccess`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy | JSON object containing the policy details. Ensure a valid policy object is passed. <br/>. | Optional | 
| policy_name | The name of the Conditional Access policy to be created. Required if policy argument not present. | Optional | 
| state | The state of the policy.<br/>Required if policy argument not present.<br/>. Possible values are: enabled, disabled. | Optional | 
| sign_in_risk_levels | List of sign-in risk levels for the policy. Options: `low`, `medium`, `high`, `none`.<br/>Required if policy argument not present.<br/>. | Optional | 
| user_risk_levels | List of user risk levels for the policy. Options: `low`, `medium`, `high`.<br/>Required if policy argument not present.<br/>. | Optional | 
| client_app_types | List of types of client apps to be included in the policy. Options: `all`, `browser`, `mobileAppsAndDesktopClients`, `exchangeActiveSync`, `easSupported`, `other`.<br/>Required if policy argument not present.<br/>. | Optional | 
| include_applications | List of application IDs to be included in the policy. If no applications are defined, `includeApplications: 'none'` will be used.<br/>. | Optional | 
| exclude_applications | List of application IDs to be excluded from the policy.<br/>. | Optional | 
| include_user_actions | List of user actions to be included in the policy.<br/>. Possible values are: vrn:user:registersecurityinfo, urn:user:registerdevice. | Optional | 
| include_users | List of user IDs to be included in the policy. Options: None, All, GuestsOrExternalUsers.<br/>. | Optional | 
| exclude_users | List of user IDs to be excluded from the policy.<br/>. | Optional | 
| include_groups | List of group IDs to be included in the policy.<br/>. | Optional | 
| exclude_groups | List of group IDs to be excluded from the policy.<br/>. | Optional | 
| include_roles | List of role IDs to be included in the policy.<br/>. | Optional | 
| exclude_roles | List of role IDs to be excluded from the policy.<br/>. | Optional | 
| include_platforms | List of platforms to be included in the policy. Options: `Android`, `iOS`, `Windows`, `windowsPhone`, `macOS`, `Linux`, `all`.<br/>. | Optional | 
| exclude_platforms | List of platforms to be excluded from the policy.<br/>. | Optional | 
| include_locations | List of location IDs to be included in the policy. Options: `All`, `AllTrusted`, or a list of specific location IDs.<br/>. | Optional | 
| exclude_locations | List of location IDs to be excluded from the policy.<br/>. | Optional | 
| grant_control_operator | The operator for grant control.<br/>Default value is 'AND'. Possible values are: AND, OR. Default is AND. | Optional | 
| grant_control_enforcement | List of built-in controls for the policy. Options: `block`, `mfa`, `compliantDevice`, `domainJoinedDevice`, `approvedApplication`, `compliantApplication`, `passwordChange`.<br/>Default value is 'mfa'<br/>Special considerations when using `passwordChange`: <br/>- `passwordChange` must be accompanied by `mfa` using an `AND` operator.<br/>- `passwordChange` must be used with `userRiskLevels`.<br/>- The policy should target all applications and not exclude any.<br/>. Default is mfa. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphIdentity.ConditionalAccessPolicy.id | string | The unique ID of the Conditional Access policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.displayName | string | The display name of the Conditional Access policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.createdDateTime | date | The date and time the policy was created. | 
| MSGraphIdentity.ConditionalAccessPolicy.modifiedDateTime | date | The date and time the policy was last modified. | 
| MSGraphIdentity.ConditionalAccessPolicy.state | string | The state of the policy \(enabled/disabled\). | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.signInRiskLevels | list | List of sign-in risk levels this policy applies to. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.clientAppTypes | list | Client application types this policy targets. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.applications.includeApplications | list | List of applications included in the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.applications.excludeApplications | list | List of applications excluded from the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.applications.includeUserActions | list | User actions included in the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.users.includeUsers | list | User IDs included in the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.users.excludeUsers | list | User IDs excluded from the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.users.includeGroups | list | Group IDs included in the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.users.excludeGroups | list | Group IDs excluded from the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.users.includeRoles | list | Role IDs included in the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.users.excludeRoles | list | Role IDs excluded from the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.platforms.includePlatforms | list | Platforms included in the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.platforms.excludePlatforms | list | Platforms excluded from the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.locations.includeLocations | list | Location IDs included in the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.locations.excludeLocations | list | Location IDs excluded from the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.grantControls.operator | string | Logical operator used in the grant controls \(e.g., AND, OR\). | 
| MSGraphIdentity.ConditionalAccessPolicy.grantControls.builtInControls | list | List of built-in access controls \(e.g., MFA, compliant device\). | 
| MSGraphIdentity.ConditionalAccessPolicy.grantControls.customAuthenticationFactors | list | Custom authentication factors used in the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.grantControls.termsOfUse | list | List of Terms of Use policy IDs applied. | 
| MSGraphIdentity.ConditionalAccessPolicy.sessionControls.cloudAppSecurity.cloudAppSecurityType | string | The type of cloud app security control. | 
| MSGraphIdentity.ConditionalAccessPolicy.sessionControls.cloudAppSecurity.isEnabled | boolean | Whether cloud app security is enabled. | 
| MSGraphIdentity.ConditionalAccessPolicy.sessionControls.signInFrequency.value | number | Sign-in frequency value. | 
| MSGraphIdentity.ConditionalAccessPolicy.sessionControls.signInFrequency.type | string | Unit of the sign-in frequency \(e.g., hours, days\). | 
| MSGraphIdentity.ConditionalAccessPolicy.sessionControls.signInFrequency.isEnabled | boolean | Whether sign-in frequency control is enabled. | 

#### Command example
```!msgraph-identity-ca-policy-create policy_name="test" state=disabled client_app_types="all" include_users="All" include_applications="none" include_platforms="iOS" grant_control_enforcement="block" grant_control_operator="AND" sign_in_risk_levels="low" user_risk_levels="low"```
#### Context Example
```json
{
    "MSGraphIdentity": {
        "ConditionalAccessPolicy": {
            "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies/$entity",
            "conditions": {
                "applications": {
                    "applicationFilter": null,
                    "excludeApplications": [],
                    "includeApplications": [
                        "None"
                    ],
                    "includeAuthenticationContextClassReferences": [],
                    "includeUserActions": []
                },
                "authenticationFlows": null,
                "clientAppTypes": [
                    "all"
                ],
                "clientApplications": null,
                "devices": null,
                "insiderRiskLevels": null,
                "locations": null,
                "platforms": {
                    "excludePlatforms": [],
                    "includePlatforms": [
                        "iOS"
                    ]
                },
                "servicePrincipalRiskLevels": [],
                "signInRiskLevels": [
                    "low"
                ],
                "userRiskLevels": [
                    "low"
                ],
                "users": {
                    "excludeGroups": [],
                    "excludeGuestsOrExternalUsers": null,
                    "excludeRoles": [],
                    "excludeUsers": [],
                    "includeGroups": [],
                    "includeGuestsOrExternalUsers": null,
                    "includeRoles": [],
                    "includeUsers": [
                        "All"
                    ]
                }
            },
            "createdDateTime": "2025-05-15T14:11:02.0356168Z",
            "displayName": "test",
            "grantControls": {
                "authenticationStrength": null,
                "authenticationStrength@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('0a31b9ab-be62-4f1b-b4a7-523940eb9f54')/grantControls/authenticationStrength/$entity",
                "builtInControls": [
                    "block"
                ],
                "customAuthenticationFactors": [],
                "operator": "OR",
                "termsOfUse": []
            },
            "id": "0a31b9ab-be62-4f1b-b4a7-523940eb9f54",
            "modifiedDateTime": null,
            "sessionControls": null,
            "state": "disabled",
            "templateId": null
        }
    }
}
```

#### Human Readable Output

>Conditional Access policy 0a31b9ab-be62-4f1b-b4a7-523940eb9f54 was successfully created.

### msgraph-identity-ca-policy-update

***
Updates a Conditional Access policy. By default, the command attempts to **append** values to existing list-based fields (e.g., `include_users`, `include_groups`, etc.). If a field does not support appending (i.e., it's not a list), the command **overrides** the existing value with the new one.

#### Base Command

`msgraph-identity-ca-policy-update`

#### Required Permissions

`Permission type : Application or Delegated`
`Permissions:Policy.Read.All`
`Policy.ReadWrite.ConditionalAccess`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Required. The ID of the Conditional Access policy to update. | Required | 
| policy | JSON object containing the policy details. Ensure a valid policy object is passed. If no `policy` argument is provided,<br/>other required arguments like `policy_name`, `state`, etc. must be included.<br/>. | Optional | 
| policy_name | The name of the Conditional Access policy to be created. | Optional | 
| state | The state of the policy.<br/>. Possible values are: enabled, disabled. | Optional | 
| sign_in_risk_levels | List of sign-in risk levels for the policy. Options: `low`, `medium`, `high`, `none`.<br/>. | Optional | 
| user_risk_levels | List of user risk levels for the policy. Options: `low`, `medium`, `high`.<br/>. | Optional | 
| client_app_types | Types of client apps to be included in the policy. Options: `all`, `browser`, `mobileAppsAndDesktopClients`, `exchangeActiveSync`, `easSupported`, `other`.<br/>. | Optional | 
| include_applications | List of application IDs to be included in the policy. If no applications are defined, `includeApplications: 'none'` will be used.<br/>. | Optional | 
| exclude_applications | List of application IDs to be excluded from the policy.<br/>. | Optional | 
| include_user_actions | List of user actions to be included in the policy. Options: `vrn:user:registersecurityinfo`, `urn:user:registerdevice`.<br/>. Possible values are: vrn:user:registersecurityinfo, urn:user:registerdevice. | Optional | 
| include_users | List of user IDs to be included in the policy. Options: None, All, GuestsOrExternalUsers.<br/>. | Optional | 
| exclude_users | List of user IDs to be excluded from the policy.<br/>. | Optional | 
| include_groups | List of group IDs to be included in the policy.<br/>. | Optional | 
| exclude_groups | List of group IDs to be excluded from the policy.<br/>. | Optional | 
| include_roles | List of role IDs to be included in the policy.<br/>. | Optional | 
| exclude_roles | List of role IDs to be excluded from the policy.<br/>. | Optional | 
| include_platforms | List of platforms to be included in the policy. Options: `Android`, `iOS`, `Windows`, `windowsPhone`, `macOS`, `Linux`, `all`.<br/>. | Optional | 
| exclude_platforms | List of platforms to be excluded from the policy.<br/>. | Optional | 
| include_locations | List of location IDs to be included in the policy. Options: `All`, `AllTrusted`, or a list of specific location IDs.<br/>. | Optional | 
| exclude_locations | List of location IDs to be excluded from the policy.<br/>. | Optional | 
| grant_control_operator | The operator for grant control.<br/>. Possible values are: AND, OR. | Optional | 
| grant_control_enforcement | List of built-in controls for the policy. Options: `block`, `mfa`, `compliantDevice`, `domainJoinedDevice`, `approvedApplication`, `compliantApplication`, `passwordChange`.<br/>Special considerations when using `passwordChange`: <br/>- `passwordChange` must be accompanied by `mfa` using an `AND` operator.<br/>- `passwordChange` must be used with `userRiskLevels`.<br/>- The policy should target all applications and not exclude any.<br/>. | Optional | 
| update_action | Defines how to update fields in the policy.<br/>- `override` (default): Replaces existing values.<br/>- `append`: Adds new values to existing ones without removing them.<br/>. Possible values are: override, append. | Optional | 

#### Context Output

There is no context output for this command.
#### Command example
```!msgraph-identity-ca-policy-update policy_id="58c3a52b-190f-4be3-a19c-a4d03f8ce684" state="disabled"```

#### Human Readable Output

>Conditional Access policy 58c3a52b-190f-4be3-a19c-a4d03f8ce684 was successfully updated.
>
>Note:
>Field `state` is not a list - overriding the value.

### msgraph-identity-ca-policies-list

***
Retrieve one or all Conditional Access policies from Microsoft Graph API.

#### Base Command

`msgraph-identity-ca-policies-list`

#### Required Permissions

`Permission type : Application or Delegated`
`Permissions:Policy.Read.All`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Optional. The ID of the Conditional Access policy to retrieve. If not provided, all policies will be returned. | Optional | 
| filter | Optional. The OData filter query to retrieve specific Conditional Access policies. | Optional | 
| limit | Optional. The maximum number of Conditional Access policies to return. Applicable only when all_results is set to false. | Optional | 
| all_results | Optional. Whether to retrieve all results without applying the 'limit'. Default value is true. Possible values are: true, false. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| MSGraphIdentity.ConditionalAccessPolicy.id | string | The unique ID of the Conditional Access policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.displayName | string | The display name of the Conditional Access policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.createdDateTime | date | The date and time the policy was created. | 
| MSGraphIdentity.ConditionalAccessPolicy.modifiedDateTime | date | The date and time the policy was last modified. | 
| MSGraphIdentity.ConditionalAccessPolicy.state | string | The state of the policy \(enabled/disabled\). | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.signInRiskLevels | list | List of sign-in risk levels this policy applies to. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.clientAppTypes | list | Client application types this policy targets. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.applications.includeApplications | list | List of applications included in the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.applications.excludeApplications | list | List of applications excluded from the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.applications.includeUserActions | list | User actions included in the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.users.includeUsers | list | User IDs included in the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.users.excludeUsers | list | User IDs excluded from the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.users.includeGroups | list | Group IDs included in the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.users.excludeGroups | list | Group IDs excluded from the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.users.includeRoles | list | Role IDs included in the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.users.excludeRoles | list | Role IDs excluded from the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.platforms.includePlatforms | list | Platforms included in the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.platforms.excludePlatforms | list | Platforms excluded from the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.locations.includeLocations | list | Location IDs included in the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.conditions.locations.excludeLocations | list | Location IDs excluded from the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.grantControls.operator | string | Logical operator used in the grant controls \(e.g., AND, OR\). | 
| MSGraphIdentity.ConditionalAccessPolicy.grantControls.builtInControls | list | List of built-in access controls \(e.g., MFA, compliant device\). | 
| MSGraphIdentity.ConditionalAccessPolicy.grantControls.customAuthenticationFactors | list | Custom authentication factors used in the policy. | 
| MSGraphIdentity.ConditionalAccessPolicy.grantControls.termsOfUse | list | List of Terms of Use policy IDs applied. | 
| MSGraphIdentity.ConditionalAccessPolicy.sessionControls.cloudAppSecurity.cloudAppSecurityType | string | The type of cloud app security control. | 
| MSGraphIdentity.ConditionalAccessPolicy.sessionControls.cloudAppSecurity.isEnabled | boolean | Whether cloud app security is enabled. | 
| MSGraphIdentity.ConditionalAccessPolicy.sessionControls.signInFrequency.value | number | Sign-in frequency value. | 
| MSGraphIdentity.ConditionalAccessPolicy.sessionControls.signInFrequency.type | string | Unit of the sign-in frequency \(e.g., hours, days\). | 
| MSGraphIdentity.ConditionalAccessPolicy.sessionControls.signInFrequency.isEnabled | boolean | Whether sign-in frequency control is enabled. | 

#### Command example
```!msgraph-identity-ca-policies-list limit=2 all_results=false```
#### Context Example
```json
{
    "MSGraphIdentity": {
        "ConditionalAccessPolicy": [
            {
                "conditions": {
                    "applications": {
                        "applicationFilter": null,
                        "excludeApplications": [],
                        "includeApplications": [
                            "Office365"
                        ],
                        "includeAuthenticationContextClassReferences": [],
                        "includeUserActions": []
                    },
                    "authenticationFlows": null,
                    "clientAppTypes": [
                        "all"
                    ],
                    "clientApplications": null,
                    "devices": null,
                    "insiderRiskLevels": null,
                    "locations": {
                        "excludeLocations": [],
                        "includeLocations": [
                            "All"
                        ]
                    },
                    "platforms": null,
                    "servicePrincipalRiskLevels": [],
                    "signInRiskLevels": [],
                    "userRiskLevels": [],
                    "users": {
                        "excludeGroups": [],
                        "excludeGuestsOrExternalUsers": null,
                        "excludeRoles": [],
                        "excludeUsers": [],
                        "includeGroups": [],
                        "includeGuestsOrExternalUsers": null,
                        "includeRoles": [],
                        "includeUsers": [
                            "d629c370-61c9-4851-8f3d-80ea6c07655f"
                        ]
                    }
                },
                "createdDateTime": "2025-02-12T11:58:25.6358652Z",
                "displayName": "block office test policy",
                "grantControls": {
                    "authenticationStrength": null,
                    "authenticationStrength@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('24d40f2e-1998-4bf1-96ff-db841b6d51e6')/grantControls/authenticationStrength/$entity",
                    "builtInControls": [
                        "mfa"
                    ],
                    "customAuthenticationFactors": [],
                    "operator": "OR",
                    "termsOfUse": []
                },
                "id": "24d40f2e-1998-4bf1-96ff-db841b6d51e6",
                "modifiedDateTime": "2025-02-13T06:51:23.575868Z",
                "sessionControls": null,
                "state": "disabled",
                "templateId": null
            },
            {
                "conditions": {
                    "applications": {
                        "applicationFilter": null,
                        "excludeApplications": [],
                        "includeApplications": [
                            "All"
                        ],
                        "includeAuthenticationContextClassReferences": [],
                        "includeUserActions": []
                    },
                    "authenticationFlows": null,
                    "clientAppTypes": [
                        "all"
                    ],
                    "clientApplications": null,
                    "devices": null,
                    "insiderRiskLevels": null,
                    "locations": null,
                    "platforms": null,
                    "servicePrincipalRiskLevels": [],
                    "signInRiskLevels": [
                        "high"
                    ],
                    "userRiskLevels": [],
                    "users": {
                        "excludeGroups": [],
                        "excludeGuestsOrExternalUsers": null,
                        "excludeRoles": [],
                        "excludeUsers": [],
                        "includeGroups": [
                            "66b0b57b-25c5-4ef3-9d4f-b7bdea0e8794"
                        ],
                        "includeGuestsOrExternalUsers": null,
                        "includeRoles": [],
                        "includeUsers": []
                    }
                },
                "createdDateTime": "2025-02-12T22:01:32.2461656Z",
                "displayName": "Microsoft-managed: Multifactor authentication and reauthentication for risky sign-ins",
                "grantControls": {
                    "authenticationStrength": null,
                    "authenticationStrength@odata.context": "https://graph.microsoft.com/v1.0/$metadata#identity/conditionalAccess/policies('f1b54946-07ee-4c43-a78a-3f33ee248495')/grantControls/authenticationStrength/$entity",
                    "builtInControls": [
                        "mfa"
                    ],
                    "customAuthenticationFactors": [],
                    "operator": "OR",
                    "termsOfUse": []
                },
                "id": "f1b54946-07ee-4c43-a78a-3f33ee248495",
                "modifiedDateTime": "2025-05-14T20:18:55.0820676Z",
                "sessionControls": {
                    "applicationEnforcedRestrictions": null,
                    "cloudAppSecurity": null,
                    "disableResilienceDefaults": null,
                    "persistentBrowser": null,
                    "signInFrequency": {
                        "authenticationType": "primaryAndSecondaryAuthentication",
                        "frequencyInterval": "everyTime",
                        "isEnabled": true,
                        "type": null,
                        "value": null
                    }
                },
                "state": "enabled",
                "templateId": "4200930c-0da2-4e33-ca01-000000000007"
            }
        ]
    }
}
```

#### Human Readable Output

>### Conditional Access Policies
>|CreatedDateTime|DisplayName|ID|IncludeUsers|State|
>|---|---|---|---|---|
>| 2025-02-12T11:58:25.6358652Z | block office test policy | 24d40f2e-1998-4bf1-96ff-db841b6d51e6 | d629c370-61c9-4851-8f3d-80ea6c07655f | disabled |
>| 2025-02-12T22:01:32.2461656Z | Microsoft-managed: Multifactor authentication and reauthentication for risky sign-ins | f1b54946-07ee-4c43-a78a-3f33ee248495 |  | enabled |


### msgraph-identity-ca-policy-delete

***
Delete specific Conditional Access policy by ID.

#### Base Command

`msgraph-identity-ca-policy-delete`

#### Required Permissions

`Permission type : Application or Delegated`
`Permissions:Policy.Read.All`
`Policy.ReadWrite.ConditionalAccess`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_id | Required. The ID of the Conditional Access policy to delete. | Required | 

#### Context Output

There is no context output for this command.

#### Command example
```!msgraph-identity-ca-policy-delete policy_id="fc271abb-e52c-4c40-aff9-5fd1e534a58d"```

#### Human Readable Output
>Conditional Access policy fc271abb-e52c-4c40-aff9-5fd1e534a58d was successfully deleted.