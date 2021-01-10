> <i>Note:</i> This integration should be used along with our IAM premium pack. For further details, visit our IAM pack documentation.

Integrate with Salesforce's services to perform Identity Lifecycle Management operations.
For more information, please refer to the [Identity Lifecycle Management article](https://xsoar.pan.dev/docs/reference/articles/identity-lifecycle-management).

## Configure Salesforce IAM on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Salesforce IAM.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Salesforce url \(Eg: https://&amp;lt;domain&amp;gt;.salesforce.com/\) | True |
| credentials | User name | True |
| consumer_key | Consumer Key | True |
| consumer_secret | Consumer Secret | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| create_user_enabled | Create User Command Enabled | False |
| update_user_enabled | Update User Command Enabled | False |
| disable_user_enabled | Disable User Commands Enabled | False |
| create_if_not_exists | Automatically create user if not found in update and enable commands | False |
| mapper_in | Incoming Mapper | True |
| mapper_out | Outgoing Mapper | True |
| localesidkey | Default Local Sid Key | False |
| emailencodingkey | Default Email Encoding Key | False |
| languagelocalekey | Default Language Locale Key | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### iam-create-user
***
Creates a user.
In order to create a user some mandatory fields are required, such as Local Sid Key, Email Encoding Key and Language Locale Key
that can be set as default in the integration's param, ProfileId and Time Zone Sid Key should be mapped using a suitable transformer,
for example, look at the demo transformers scripts - DemoGenerateTimeZone and DemoGenerateProfileId.
Please create your own transformers and map the fitting values to them.

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
``` !iam-create-user user-profile=`{"email":"testdemisto2@paloaltonetworks.com", "givenname":"Test","surname":"Demisto”,”timezonesidkey": "Asia/Tokyo",“localesidkey": "en_US",“profileid": “012345678912345”}` ```
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

### iam-enable-user
***
Enables a deprovisioned user.


#### Base Command

`iam-enable-user`
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
``` ```

#### Human Readable Output



### get-mapping-fields
***
Retrieves a User Profile schema which holds all of the user fields within the application. Used for outgoing-mapping through the Get Schema option.


#### Base Command

`get-mapping-fields`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output


