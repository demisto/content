> <i>Note:</i> This integration should be used along with our IAM premium pack. For further details, visit our IAM pack documentation.

Integrate with Salesforce's services to perform Identity Lifecycle Management operations.
For more information, please refer to the [Identity Lifecycle Management article](https://xsoar.pan.dev/docs/reference/articles/identity-lifecycle-management).

## Configure Salesforce IAM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Salesforce IAM.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Salesforce url (Eg: https://&lt;domain&gt;.salesforce.com/) | True |
    | User name | True |
    | Password | True |
    | Consumer Key | True |
    | Consumer Secret | True |
    | Allow creating users | False |
    | Allow updating users | False |
    | Allow enabling users | False |
    | Allow disabling users | False |
    | Automatically create user if not found in update and enable commands | False |
    | Incoming Mapper | True |
    | Outgoing Mapper | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### iam-create-user
***
Creates a user.


#### Base Command

`iam-create-user`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | User Profile indicator details. | Required | 
| allow-enable | When set to true, after the command execution the status of the user in the 3rd-party integration will be active. Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | If true the employee's status is active, otherwise false. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Gives the user information if the API was successful, otherwise error information. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | If true, the command was executed successfully, otherwise false. | 
| IAM.Vendor.username | String | The employee's username in the app. | 


#### Command Example
``` !iam-create-user user-profile=`{"email":"testdemisto2@paloaltonetworks.com", "givenname":"Test","surname":"Demisto","TimeZoneSidKey": "Asia/Tokyo","ProfileId": "012345678912345"}` ```
#### Human Readable Output
|brand|instanceName|success|active|id|email|details|
|---|---|---|---|---|---|---|
| Salesforce IAM | Salesforce IAM_instance_1 | true | true | edab746f1b142410042611b4bd4bcb23 | testdemisto2@paloaltonetworks.com | 



### iam-update-user
***
Updates an existing user with the data passed in the user-profile argument.


#### Base Command

`iam-update-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator. | Required | 
| allow-enable | When set to true, after the command execution the status of the user in the 3rd-party integration will be active. Possible values are: true, false. Default is true. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | If true the employee's status is active, otherwise false. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Gives the user information if the API was successful, otherwise error information. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | If true, the command was executed successfully, otherwise false. | 
| IAM.Vendor.username | String | The employee's username in the app. | 


#### Command Example
``` !iam-update-user user-profile=`{"email":"testdemisto2@paloaltonetworks.com", "givenname":"Test","surname":"Demisto_updated"}` ```

#### Human Readable Output
|brand|instanceName|success|active|id|email|details|
|---|---|---|---|---|---|---|
| Salesforce IAM | Salesforce IAM_instance_1 | true | true | edab746f1b142410042611b4bd4bcb23 | testdemisto2@paloaltonetworks.com | 



### iam-get-user
***
Retrieves a single user resource.


#### Base Command

`iam-get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | If true the employee's status is active, otherwise false. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Gives the user information if the API was successful, otherwise error information. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | If true, the command was executed successfully, otherwise false. | 
| IAM.Vendor.username | String | The employee's username in the app. | 



#### Command Example
``` !iam-get-user user-profile=`{"email":"testdemisto2@paloaltonetworks.com"}` ```

#### Human Readable Output
|brand|instanceName|success|active|id|email|details|
|---|---|---|---|---|---|---|
| Salesforce IAM | Salesforce IAM_instance_1 | true | true | edab746f1b142410042611b4bd4bcb23 | testdemisto2@paloaltonetworks.com | "AboutMe": null, "AccountId": null, "Address": null, "Alias": "testdemi", "BadgeText": "", "BannerPhotoUrl": "/profilephoto/", "CallCenterId": null, "City": null, "CommunityNickname": "User1", "CompanyName": null, "ContactId": null, "Country": null, "CreatedById": "123", "CreatedDate": "2020-12-29T09:07:00.000+0000", "DefaultGroupNotificationFrequency": "N", "DelegatedApproverId": null, "Department": null, "DigestFrequency": "D", "Division": null, "Email": "testdemisto2@paloaltonetworks.com", "EmailEncodingKey": "ISO-8859-1", "EmailPreferencesAutoBcc": true, "EmailPreferencesAutoBccStayInTouch": false, "EmailPreferencesStayInTouchReminder": true, "EmployeeNumber": null, "Extension": null, "Fax": null, "FederationIdentifier": null, "FirstName": "test", "ForecastEnabled": false, "FullPhotoUrl": "https://profilephoto/", "GeocodeAccuracy": null, "Id": "123", "IndividualId": null, "IsActive": true, "IsExtIndicatorVisible": false, "IsProfilePhotoActive": false, "JigsawImportLimitOverride": null, "LanguageLocaleKey": "en_US", "LastLoginDate": null, "LastModifiedById": "0054K000001WwcuQAC", "LastModifiedDate": "2021-01-03T13:53:24.000+0000","LastName": "test2", "LastPasswordChangeDate": null, "LastReferencedDate": "2021-01-03T14:14:00.000+0000", "LastViewedDate": "2021-01-03T14:14:00.000+0000", "Latitude": null, "LocaleSidKey": "en_US", "Longitude": null, "ManagerId": null, "MediumBannerPhotoUrl": "/profilephoto/", "MediumPhotoUrl": "https:/profilephoto/", "MobilePhone": null, "Name": "test", "OfflinePdaTrialExpirationDate": null, "OfflineTrialExpirationDate": null, "OutOfOfficeMessage": "", "Phone": null, "PostalCode": null, "ProfileId": "012345678912345", "ReceivesAdminInfoEmails": false, "ReceivesInfoEmails": false, "SenderEmail": null, "SenderName": null, "Signature": null, "SmallBannerPhotoUrl": "/profilephoto/", "SmallPhotoUrl": "profilephoto", "State": null, "StayInTouchNote": null, "StayInTouchSignature": null, "StayInTouchSubject": null, "Street": null, "SystemModstamp": "2021-01-03T13:53:24.000+0000", "TimeZoneSidKey": "Asia/Tokyo", "Title": null, "UserPermissionsCallCenterAutoLogin": false, "UserPermissionsInteractionUser": false, "UserPermissionsJigsawProspectingUser": false, "UserPermissionsKnowledgeUser": false, "UserPermissionsMarketingUser": false, "UserPermissionsMobileUser": false, "UserPermissionsOfflineUser": false, "UserPermissionsSFContentUser": true, "UserPermissionsSiteforceContributorUser": false, "UserPermissionsSiteforcePublisherUser": false, "UserPermissionsSupportUser": false, "UserPermissionsWorkDotComUserFeature": false, "UserPreferencesActivityRemindersPopup": true, "UserPreferencesApexPagesDeveloperMode": false, "UserPreferencesCacheDiagnostics": false, "UserPreferencesContentEmailAsAndWhen": false, "UserPreferencesContentNoEmail": false, "UserPreferencesCreateLEXAppsWTShown": false, "UserPreferencesDisCommentAfterLikeEmail": false, "UserPreferencesDisMentionsCommentEmail": false, "UserPreferencesDisProfPostCommentEmail": false, "UserPreferencesDisableAllFeedsEmail": false, "UserPreferencesDisableBookmarkEmail": false, "UserPreferencesDisableChangeCommentEmail": false, "UserPreferencesDisableEndorsementEmail": false, "UserPreferencesDisableFeedbackEmail": false, "UserPreferencesDisableFileShareNotificationsForApi": false, "UserPreferencesDisableFollowersEmail": false, "UserPreferencesDisableLaterCommentEmail": false, "UserPreferencesDisableLikeEmail": true, "UserPreferencesDisableMentionsPostEmail": false, "UserPreferencesDisableMessageEmail": false, "UserPreferencesDisableProfilePostEmail": false, "UserPreferencesDisableSharePostEmail": false, "UserPreferencesDisableWorkEmail": false, "UserPreferencesEnableAutoSubForFeeds": false, "UserPreferencesEventRemindersCheckboxDefault": true, "UserPreferencesExcludeMailAppAttachments": false, "UserPreferencesFavoritesShowTopFavorites": false, "UserPreferencesFavoritesWTShown": false, "UserPreferencesGlobalNavBarWTShown": false, "UserPreferencesGlobalNavGridMenuWTShown": false, "UserPreferencesHasCelebrationBadge": false, "UserPreferencesHideBiggerPhotoCallout": false, "UserPreferencesHideCSNDesktopTask": false, "UserPreferencesHideCSNGetChatterMobileTask": false, "UserPreferencesHideChatterOnboardingSplash": false, "UserPreferencesHideEndUserOnboardingAssistantModal": false, "UserPreferencesHideLightningMigrationModal": false, "UserPreferencesHideS1BrowserUI": false, "UserPreferencesHideSecondChatterOnboardingSplash": false, "UserPreferencesHideSfxWelcomeMat": true, "UserPreferencesJigsawListUser": false, "UserPreferencesLightningExperiencePreferred": true, "UserPreferencesNewLightningReportRunPageEnabled": false, "UserPreferencesPathAssistantCollapsed": false, "UserPreferencesPipelineViewHideHelpPopover": false, "UserPreferencesPreviewCustomTheme": false, "UserPreferencesPreviewLightning": false, "UserPreferencesRecordHomeReservedWTShown": false, "UserPreferencesRecordHomeSectionCollapseWTShown": false, "UserPreferencesReminderSoundOff": false, "UserPreferencesShowCityToExternalUsers": false, "UserPreferencesShowCityToGuestUsers": false, "UserPreferencesShowCountryToExternalUsers": false, "UserPreferencesShowCountryToGuestUsers": false, "UserPreferencesShowEmailToExternalUsers": false, "UserPreferencesShowEmailToGuestUsers": false, "UserPreferencesShowFaxToExternalUsers": false, "UserPreferencesShowFaxToGuestUsers": false, "UserPreferencesShowManagerToExternalUsers": false, "UserPreferencesShowManagerToGuestUsers": false, "UserPreferencesShowMobilePhoneToExternalUsers": false, "UserPreferencesShowMobilePhoneToGuestUsers": false, "UserPreferencesShowPostalCodeToExternalUsers": false, "UserPreferencesShowPostalCodeToGuestUsers": false, "UserPreferencesShowProfilePicToGuestUsers": false, "UserPreferencesShowStateToExternalUsers": false, "UserPreferencesShowStateToGuestUsers": false, "UserPreferencesShowStreetAddressToExternalUsers": false, "UserPreferencesShowStreetAddressToGuestUsers": false, "UserPreferencesShowTitleToExternalUsers": true, "UserPreferencesShowTitleToGuestUsers": false, "UserPreferencesShowWorkPhoneToExternalUsers": false, "UserPreferencesShowWorkPhoneToGuestUsers": false, "UserPreferencesSortFeedByComment": true, "UserPreferencesSuppressEventSFXReminders": false, "UserPreferencesSuppressTaskSFXReminders": false, "UserPreferencesTaskRemindersCheckboxDefault": true, "UserPreferencesUserDebugModePref": false, "UserRoleId": null, "UserType": "Standard", "Username": "testdemisto2@paloaltonetworks.com",



### iam-disable-user
***
Disable an active user.


#### Base Command

`iam-disable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user-profile | A User Profile indicator. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.active | Boolean | If true the employee's status is active, otherwise false. | 
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.details | string | Gives the user information if the API was successful, otherwise error information. | 
| IAM.Vendor.email | String | The employee's email address. | 
| IAM.Vendor.errorCode | Number | HTTP error response code. | 
| IAM.Vendor.errorMessage | String | Reason why the API failed. | 
| IAM.Vendor.id | String | The employee's user ID in the app. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.success | Boolean | If true, the command was executed successfully, otherwise false. | 
| IAM.Vendor.username | String | The employee's username in the app. | 



#### Command Example
``` !iam-disable-user user-profile=`{"email":"testdemisto2@paloaltonetworks.com"}` ```

#### Human Readable Output
|brand|instanceName|success|active|id|email|details|
|---|---|---|---|---|---|---|
| Salesforce IAM | Salesforce IAM_instance_1 | true | false | edab746f1b142410042611b4bd4bcb23 | testdemisto2@paloaltonetworks.com | 




### get-mapping-fields
***
Retrieves a User Profile schema which holds all of the user fields within the application. Used for outgoing-mapping through the Get Schema option.


### salesforce-assign-permission-set
***
Assigns a permission set for a user.


#### Base Command

`salesforce-assign-permission-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID. | Required | 
| permission_set_id | Permission set ID of the user. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.action | String | The command name. | 
| IAM.Vendor.success | boolean | Status of the result. Can be true or false. | 
| IAM.Vendor.PermissionSetAssign.id | string | ID of the created permission set assignment. | 
| IAM.Vendor.errorCode | string | Error code from API, displayed in case of failure. | 
| IAM.Vendor.errorMessage | string | Error message from API, displayed in case of failure. | 


#### Command Example
``` ```

#### Human Readable Output



### salesforce-get-assigned-permission-set
***
Gets the assigned permission set.


#### Base Command

`salesforce-get-assigned-permission-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.action | String | The command name. | 
| IAM.Vendor.success | boolean | Status of the result. Can be true or false. | 
| IAM.Vendor.PermissionSetAssignments.attributes | string | Information about the type and the url of the field fetched. | 
| IAM.Vendor.PermissionSetAssignments.AssigneeId | string | User ID passed as an input. | 
| IAM.Vendor.PermissionSetAssignments.Id | string | ID of the created permission set assignment. | 
| IAM.Vendor.errorCode | string | Error code from API, displayed in case of failure. | 
| IAM.Vendor.errorMessage | string | Error message from API, displayed in case of failure. | 


#### Command Example
``` ```

#### Human Readable Output



### salesforce-delete-assigned-permission-set
***
Deletes an assigned permission set.


#### Base Command

`salesforce-delete-assigned-permission-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| permission_set_assignment_id | ID of the PermissionSetAssignment object. A PermissionSetAssignment represents the association between a user and a permission set. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.action | String | The command name. | 
| IAM.Vendor.success | boolean | Status of the result. Can be true or false. | 
| IAM.Vendor.errorCode | number | Error code from API, displayed in case of failure. | 
| IAM.Vendor.errorMessage | string | Error message from API, displayed in case of failure. | 


#### Command Example
``` ```

#### Human Readable Output



### salesforce-freeze-user-account
***
Freezes a user account.


#### Base Command

`salesforce-freeze-user-account`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_login_id | ID of UserLogin object. UserLogin - Represents the settings that affect a user's ability to log into an organization. To access this object, you need the UserPermissions.ManageUsers permission. For more details Please refer to https://developer.salesforce.com/docs/atlas.en-us.api.meta/api/sforce_api_objects_userlogin.htm. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.action | String | The command name. | 
| IAM.Vendor.success | boolean | Status of the result. Can be true or false. | 
| IAM.Vendor.errorCode | number | Error code from API, displayed in case of failure. | 
| IAM.Vendor.errorMessage | string | Error message from API, displayed in case of failure. | 


#### Command Example
``` ```

#### Human Readable Output



### salesforce-unfreeze-user-account
***
Unfreezes a user account.


#### Base Command

`salesforce-unfreeze-user-account`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_login_id | ID of the UserLogin object. UserLogin - Represents the settings that affect a user’s ability to log into an organization. To access this object, you need the UserPermissions.ManageUsers permission. For more details Please refer to https://developer.salesforce.com/docs/atlas.en-us.api.meta/api/sforce_api_objects_userlogin.htm. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.action | String | The command name. | 
| IAM.Vendor.success | boolean | Status of the result. Can be true or false. | 
| IAM.Vendor.errorCode | number | Error code from API, displayed in case of failure. | 
| IAM.Vendor.errorMessage | string | Error message from API, displayed in case of failure. | 


#### Command Example
``` ```

#### Human Readable Output



### salesforce-get-user-isfrozen-status
***
Gets a user frozen status.


#### Base Command

`salesforce-get-user-isfrozen-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.action | String | The command name. | 
| IAM.Vendor.success | boolean | Status of the result. Can be true or false. | 
| IAM.Vendor.UserIsfrozenStatus.attributes | string | Information about the type, url of the field fetched. | 
| IAM.Vendor.UserIsfrozenStatus.Id | string | ID of UserLogin object. UserLogin represents the settings that affect a user's ability to log into an organization. To access this object, you need the UserPermissions.ManageUsers permission. For more details Please refer to https://developer.salesforce.com/docs/atlas.en-us.api.meta/api/sforce_api_objects_userlogin.htm | 
| IAM.Vendor.UserIsfrozenStatus.IsFrozen | boolean | Whether the User account is in frozen state. Can be true or false. | 
| IAM.Vendor.errorCode | string | Error code from API, displayed in case of failure. | 
| IAM.Vendor.errorMessage | string | Error message from API, displayed in case of failure. | 


#### Command Example
``` ```

#### Human Readable Output



### salesforce-assign-permission-set-license
***
Assigns a permission set license.


#### Base Command

`salesforce-assign-permission-set-license`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID. | Required | 
| permission_set_license_id | Permission set license ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.action | String | The command name. | 
| IAM.Vendor.success | boolean | Status of the result. Can be true or false. | 
| IAM.Vendor.PermissionSetLicenseAssign.id | string | ID of the created ermission set assignment license. | 
| IAM.Vendor.errorCode | string | Error code from API, displayed in case of failure. | 
| IAM.Vendor.errorMessage | string | Error message from API, displayed in case of failure. | 


#### Command Example
``` ```

#### Human Readable Output



### salesforce-get-assigned-permission-set-license
***
Gets an assigned permission set license.


#### Base Command

`salesforce-get-assigned-permission-set-license`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.action | String | The command name. | 
| IAM.Vendor.success | boolean | Status of the result. Can be true or false. | 
| IAM.Vendor.PermissionSetLicenseAssignments.attributes | string | Information about the type and url of the field fetched. | 
| IAM.Vendor.PermissionSetLicenseAssignments.AssigneeId | string | User ID passed as input. | 
| IAM.Vendor.PermissionSetLicenseAssignments.Id | string | ID of the PermissionSetLicenseAssignments assigned for given user. | 
| IAM.Vendor.errorCode | string | Error code from API, displayed in case of failure. | 
| IAM.Vendor.errorMessage | string | Error message from API, displayed in case of failure. | 


#### Command Example
``` ```

#### Human Readable Output



### salesforce-delete-assigned-permission-set-license
***
Deletes an assigned permission set license.


#### Base Command

`salesforce-delete-assigned-permission-set-license`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| permission_set_assignment_license_id | ID of the PermissionSetLicenseAssign object. A PermissionSetLicenseAssign represents the association between a user and the PermissionSetLicense. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.action | String | The command name. | 
| IAM.Vendor.success | boolean | Status of the result. Can be true or false. | 
| IAM.Vendor.errorCode | string | Error code from API, displayed in case of failure. | 
| IAM.Vendor.errorMessage | string | Error message from API, displayed in case of failure. | 


#### Command Example
``` ```

#### Human Readable Output



### salesforce-assign-package-license
***
Assigns a package license.


#### Base Command

`salesforce-assign-package-license`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID. | Required | 
| package_license_id | The package License ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.action | String | The command name. | 
| IAM.Vendor.success | boolean | Status of the result. Can be true or false. | 
| IAM.Vendor.PackageLicenseAssign.id | boolean | ID of the created Package License Assign. | 
| IAM.Vendor.errorCode | number | Error code from API, displayed in case of failure. | 
| IAM.Vendor.errorMessage | string | Error message from API, displayed in case of failure. | 


#### Command Example
``` ```

#### Human Readable Output



### salesforce-get-assigned-package-license
***
Gets an assigned package license.


#### Base Command

`salesforce-get-assigned-package-license`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | The user ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.brand | String | Name of the integration. | 
| IAM.Vendor.instanceName | string | Name of the integration instance. | 
| IAM.Vendor.action | String | The command name. | 
| IAM.Vendor.success | boolean | Status of the result. Can be true or false. | 
| IAM.Vendor.PackageLicenseAssignments.attributes | boolean | Information about the type and url of the field fetched. | 
| IAM.Vendor.PackageLicenseAssignments.AssigneeId | string | User ID passed as input. | 
| IAM.Vendor.PackageLicenseAssignments.Id | string | ID of the Package License Assignment of the given user. | 
| IAM.Vendor.errorCode | number | Error code from API, displayed in case of failure. | 
| IAM.Vendor.errorMessage | string | Error message from API, displayed in case of failure. | 


#### Command Example
``` ```

#### Human Readable Output



### salesforce-delete-assigned-package-license
***
Deletes an assigned package license.


#### Base Command

`salesforce-delete-assigned-package-license`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_package_license_id | ID of the UserPackageLicense object. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IAM.Vendor.success | boolean | Status of the result. Can be true or false. | 
| IAM.Vendor.errorCode | number | Error code from API, displayed in case of failure. | 
| IAM.Vendor.errorMessage | string | Error message from API, displayed in case of failure. | 


#### Command Example
``` ```

#### Human Readable Output


