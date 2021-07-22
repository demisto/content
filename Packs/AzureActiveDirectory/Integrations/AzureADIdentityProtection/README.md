Get information from Azure Active Directory Identity Protection service.
This integration was integrated and tested with the Beta version of Azure Active Directory Identity Protection

## Configure Azure Active Directory Identity Protection on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Azure Active Directory Identity Protection.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Application ID |  | True |
    | Subscription ID |  | True |
    | Resource Group Name |  | True |
    | Azure AD endpoint | Azure AD endpoint associated with a national cloud. | True |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### azure-ad-auth-test
***
Tests the connectivity to Azure.


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
Run this command to start the authorization process and follow the instructions in the command results.


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
>and enter the code **CY9ZQLAT8** to authenticate.
>2. Run the **!azure-ad-auth-complete** command in the War Room.

### azure-ad-auth-complete
***
Run this command to complete the authorization process. Should be used after running the azure-ad-auth-start command.


#### Base Command

`azure-ad-auth-complete`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



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
``` ```

#### Human Readable Output



### azure-ad-identity-protection-risks-list
***
Retrieve the properties of a collection of riskDetection objects.


#### Base Command

`azure-ad-identity-protection-risks-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Unique ID of the risk detection. | Optional | 
| user_id | Unique ID of the user. | Optional | 
| user_principal_name | The user principal name (UPN) of the user. | Optional | 
| country | Country or region of the activity. for example, `US` or `UK`. For futher details, see https://docs.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-beta. | Optional | 
| filter_expression | A custom query by the the OData syntax. Using this overrides all arguments, except for next_link. For more details, see https://docs.microsoft.com/en-us/graph/query-parameters. | Optional | 
| limit | Number of results to provide. Default is 50. | Optional | 
| next_link | A link that specifies a starting point to use for subsequent calls. Using this argument overrides all other arguments. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### azure-ad-identity-protection-risky-user-list
***
Retrieve the properties of a collection of riskDetection objects.


#### Base Command

`azure-ad-identity-protection-risky-user-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| updated_time | The date and time that the risky user was last updated. | Optional | 
| risk_level | Level of the detected risky user. Possible values are: low, medium, high, hidden, none, unknownFeatureValue. | Optional | 
| risk_state | State of the user's risk. Possible values are: none, confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised, unknownFutureValue. | Optional | 
| risk_detail | Details of the detected risk. Possible values are: none, adminGeneratedTemporaryPassword, userPerformedSecuredPasswordChange, userPerformedSecuredPasswordReset, adminConfirmedSigninSafe, aiConfirmedSigninSafe, userPassedMFADrivenByRiskBasedPolicy, adminDismissedAllRiskForUser, adminConfirmedSigninCompromised, hidden, adminConfirmedUserCompromised, unknownFutureValue. | Optional | 
| filter_expression | A custom query by the the OData syntax. Using this overrides all arguments, except for next_link. For more details, see https://docs.microsoft.com/en-us/graph/query-parameters. | Optional | 
| limit | Number of results to provide. Default is 50. | Optional | 
| next_link | A link that specifies a starting point to use for subsequent calls. Using this argument overrides all other arguments. | Optional | 
| user_name | Risky user principal name. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### azure-ad-identity-protection-risky-user-history-list
***
Get the risk history of a riskyUser resource.


#### Base Command

`azure-ad-identity-protection-risky-user-history-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | Unique ID of the user. | Required | 
| limit | Number of results to provide. Default is 50. | Optional | 
| filter_expression | A custom query by the the OData syntax. Using this overrides all arguments, except for next_link. For more details, see https://docs.microsoft.com/en-us/graph/query-parameters. | Optional | 
| next_link | A link that specifies a starting point to use for subsequent calls. Using this argument overrides all other arguments. | Optional | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### azure-ad-identity-protection-risky-user-confirm-compromised
***
Confirm one or more riskyUser objects as compromised. This action sets the targeted user's risk level to high.


#### Base Command

`azure-ad-identity-protection-risky-user-confirm-compromised`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_ids | One or more user IDs, comma-separated. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output



### azure-ad-identity-protection-risky-user-dismiss
***
Dismiss the risk of one or more riskyUser objects. This action sets the targeted user's risk level to none.


#### Base Command

`azure-ad-identity-protection-risky-user-dismiss`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_ids | One or more user IDs, comma-separated. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


