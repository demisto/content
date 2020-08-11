The SalesForce API consists of a set of API endpoints that allow customers to perform CRUD operation on their user profiles.
This integration was integrated and tested with version xx of Salesforce IT Admin
## Configure Salesforce IT Admin on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Salesforce IT Admin.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Salesforce url \(Eg: https://&lt;domain&gt;.salesforce.com/\) | True |
| credentials | User name | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| client_id | Client ID | True |
| client_secret | Client secret | True |
| secret_token | Secret token | True |
| customMappingCreateUser | Custom Mapping for Create User | False |
| customMappingUpdateUser | Custom Mapping for Update User | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### get-user
***
Get a user


#### Base Command

`get-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GetUser | Unknown | Command context path | 
| GetUser.brand | String | Name of the Integration | 
| GetUser.instanceName | String | Name of the instance used for testing | 
| GetUser.success | Boolean | Status of the result. Can be true or false. | 
| GetUser.active | Boolean | Gives the active status of user. Can be true of false.  | 
| GetUser.id | String | Value of id passed as argument | 
| GetUser.username | String | Value of username passed as argument | 
| GetUser.email | String | Email ID of the user | 
| GetUser.errorCode | Number | HTTP response code other than 200 \(if there is error in response\) | 
| GetUser.errorMessage | String | Reason why the API is failed | 
| GetUser.details | String | Gives the raw response from API | 


#### Command Example
```!get-user scim={"id":"0050m000003K9VAAA0"} using=Salesforce```

#### Context Example
```
{
    "GetUser": {
        "active": false,
        "brand": "Salesforce IT Admin",
        "details": {
            "AboutMe": null,
            "AccountId": "0017000000dN0hPAAS",
            "Active_LeadAssignment__c": false,
            "Address": null,
            "Alias": "dtest",
            "Alias_Email__c": null,
            "Anaplan_Role__c": null,
            "Approver__c": null,
            "Apttus_Approval__Approval_Level__c": null,
            "Apttus_Approval__Next_Level_Approver__c": null,
            "Area__c": null,
            "BadgeText": "Customer",
            "BannerPhotoUrl": "/profilephoto/005/B",
            "Bunchball_Id__c": null,
            "CPQUserMessage__c": null,
            "CPQ_User_Name__c": null,
            "Calculated_Bunchball_ID__c": "testdemisto@pancustportal.com.sit",
            "CallCenterId": null,
            "City": null,
            "CommunityNickname": "User15943166525412354768",
            "CompanyName": null,
            "ContactId": "0030m00000XWAwYAAX",
            "Country": null,
            "Create_CPQ_User__c": false,
            "CreatedById": "0050g000005sSA2AAM",
            "CreatedDate": "2020-07-09T17:44:12.000+0000",
            "DNE__c": false,
            "Date_Deactivated__c": "2020-08-11T15:55:08.000+0000",
            "DefaultGroupNotificationFrequency": "D",
            "DelegatedApproverId": null,
            "Department": null,
            "DigestFrequency": "N",
            "Direct_Manager_Sales_Level__c": null,
            "Direct_Manager__c": null,
            "District__c": null,
            "Division": null,
            "Do_not_show_this_message_again__c": false,
            "Email": "TestID@paloaltonetworks.com",
            "EmailEncodingKey": "ISO-8859-1",
            "EmailPreferencesAutoBcc": true,
            "EmailPreferencesAutoBccStayInTouch": false,
            "EmailPreferencesStayInTouchReminder": true,
            "Email_Signature__c": null,
            "EmployeeNumber": null,
            "Employee_Code__c": "0050m000003K9VAAA0",
            "Employee_Number__c": null,
            "Exclude_Approval_Mgr_from_Workday_Update__c": false,
            "Exclude_from_Anaplan_Update__c": false,
            "Extension": null,
            "FCRM__FCR_Email_Notification_Delegate__c": null,
            "FCRM__FCR_User_Notification_Delegate__c": null,
            "Fax": null,
            "FederationIdentifier": null,
            "FirstName": "Demisto",
            "Five9__Five9AgentId__c": null,
            "Five9__Five9Agent_Login_TimeStamp__c": null,
            "ForecastEnabled": false,
            "FullPhotoUrl": "https://paloaltonetworks--sit--c.cs65.content.force.com/profilephoto/005/F",
            "Full_Name__c": "Demisto Testing",
            "GeocodeAccuracy": null,
            "GraveYard_Objects__c": null,
            "ISO_Country__c": null,
            "Id": "0050m000003K9VAAA0",
            "IndividualId": null,
            "IsActive": false,
            "IsExtIndicatorVisible": false,
            "IsMarketplace__c": false,
            "IsPortalEnabled": true,
            "IsPortalSelfRegistered": false,
            "IsProfilePhotoActive": false,
            "IsUSC__c": false,
            "LanguageLocaleKey": "en_US",
            "LastLoginDate": null,
            "LastModifiedById": "0050g000005sSA2AAM",
            "LastModifiedDate": "2020-08-11T15:55:08.000+0000",
            "LastName": "Testing",
            "LastPasswordChangeDate": null,
            "LastReferencedDate": "2020-08-11T15:55:04.000+0000",
            "LastViewedDate": "2020-08-11T15:55:04.000+0000",
            "Latitude": null,
            "Lead_Assignment__c": null,
            "LocaleSidKey": "en_US",
            "Longitude": null,
            "M_A_Id__c": null,
            "M_A_Source__c": null,
            "ManagerId": null,
            "Manager_Username__c": null,
            "Manager__c": null,
            "Managers_Sales_Level__c": null,
            "MediumBannerPhotoUrl": "/profilephoto/005/E",
            "MediumPhotoUrl": "https://paloaltonetworks--sit--c.cs65.content.force.com/profilephoto/005/M",
            "MobilePhone": null,
            "My_Backup__c": null,
            "My_Return_Date__c": null,
            "My_Sales_Level__c": "Non-Sales",
            "My_Vacation_Start_Date__c": null,
            "Name": "Demisto Testing",
            "Network_ID__c": null,
            "OfflinePdaTrialExpirationDate": null,
            "OfflineTrialExpirationDate": null,
            "OutOfOfficeMessage": "",
            "Out_of_Office__c": false,
            "Outreach_Id__c": null,
            "PANWEntity__c": null,
            "PAN_Internal_User__c": "No",
            "Phone": null,
            "PortalRole": null,
            "PostalCode": null,
            "ProfileId": "00e70000000zseOAAQ",
            "Recalculate_Partner_Sharing__c": false,
            "ReceivesAdminInfoEmails": false,
            "ReceivesInfoEmails": false,
            "Region__c": null,
            "RoundRobin_LeadCountriesAmericas__c": null,
            "RoundRobin_LeadCountriesEMEA__c": null,
            "RoundRobin_LeadCountriesROW__c": null,
            "RoundRobin_LeadCountries__c": null,
            "SBQQ__DefaultProductLookupTab__c": "Guided Selling",
            "SBQQ__DiagnosticToolEnabled__c": false,
            "SBQQ__OutputFormatChangeAllowed__c": false,
            "SBQQ__ProductSortPreference__c": null,
            "SBQQ__ResetProductLookup__c": false,
            "SBQQ__Theme__c": null,
            "SOX_Notes__c": "Enabled by XSOAR",
            "SSO_UID__c": null,
            "Sales_Coverage__c": null,
            "Sales_Specialization__c": null,
            "Search_GraveYardObjects__c": false,
            "Segment__c": null,
            "SenderEmail": null,
            "SenderName": null,
            "Signature": null,
            "SmallBannerPhotoUrl": "/profilephoto/005/D",
            "SmallPhotoUrl": "https://paloaltonetworks--sit--c.cs65.content.force.com/profilephoto/005/T",
            "State": null,
            "StayInTouchNote": null,
            "StayInTouchSignature": null,
            "StayInTouchSubject": null,
            "Street": null,
            "Support_Engineer_Location__c": null,
            "SystemModstamp": "2020-08-11T15:55:08.000+0000",
            "TMBDR__c": false,
            "TMCBM__c": false,
            "TMCSR__c": false,
            "TMCSSR__c": false,
            "TMGAM__c": false,
            "TMICBM__c": false,
            "TMMAM__c": false,
            "TMPSR__c": false,
            "TMRSM__c": false,
            "TMSBDR__c": false,
            "TMSE__c": false,
            "TMSRR__c": false,
            "Terminate_Date__c": "2020-08-04",
            "Theatre__c": null,
            "TimeZoneSidKey": "America/Los_Angeles",
            "Title": null,
            "UserPermissionsAvantgoUser": false,
            "UserPermissionsCallCenterAutoLogin": false,
            "UserPermissionsChatterAnswersUser": false,
            "UserPermissionsInteractionUser": false,
            "UserPermissionsKnowledgeUser": false,
            "UserPermissionsMarketingUser": false,
            "UserPermissionsMobileUser": false,
            "UserPermissionsOfflineUser": false,
            "UserPermissionsSFContentUser": false,
            "UserPermissionsSupportUser": false,
            "UserPreferencesActivityRemindersPopup": false,
            "UserPreferencesApexPagesDeveloperMode": false,
            "UserPreferencesCacheDiagnostics": false,
            "UserPreferencesContentEmailAsAndWhen": false,
            "UserPreferencesContentNoEmail": false,
            "UserPreferencesCreateLEXAppsWTShown": false,
            "UserPreferencesDisCommentAfterLikeEmail": false,
            "UserPreferencesDisMentionsCommentEmail": false,
            "UserPreferencesDisProfPostCommentEmail": false,
            "UserPreferencesDisableAllFeedsEmail": false,
            "UserPreferencesDisableBookmarkEmail": false,
            "UserPreferencesDisableChangeCommentEmail": false,
            "UserPreferencesDisableEndorsementEmail": false,
            "UserPreferencesDisableFileShareNotificationsForApi": false,
            "UserPreferencesDisableFollowersEmail": false,
            "UserPreferencesDisableLaterCommentEmail": false,
            "UserPreferencesDisableLikeEmail": true,
            "UserPreferencesDisableMentionsPostEmail": false,
            "UserPreferencesDisableMessageEmail": false,
            "UserPreferencesDisableProfilePostEmail": false,
            "UserPreferencesDisableSharePostEmail": false,
            "UserPreferencesEnableAutoSubForFeeds": false,
            "UserPreferencesEventRemindersCheckboxDefault": false,
            "UserPreferencesExcludeMailAppAttachments": false,
            "UserPreferencesFavoritesShowTopFavorites": false,
            "UserPreferencesFavoritesWTShown": false,
            "UserPreferencesGlobalNavBarWTShown": false,
            "UserPreferencesGlobalNavGridMenuWTShown": false,
            "UserPreferencesHasCelebrationBadge": false,
            "UserPreferencesHideBiggerPhotoCallout": false,
            "UserPreferencesHideCSNDesktopTask": false,
            "UserPreferencesHideCSNGetChatterMobileTask": false,
            "UserPreferencesHideChatterOnboardingSplash": false,
            "UserPreferencesHideEndUserOnboardingAssistantModal": false,
            "UserPreferencesHideLightningMigrationModal": false,
            "UserPreferencesHideS1BrowserUI": false,
            "UserPreferencesHideSecondChatterOnboardingSplash": false,
            "UserPreferencesHideSfxWelcomeMat": true,
            "UserPreferencesLightningExperiencePreferred": true,
            "UserPreferencesNewLightningReportRunPageEnabled": false,
            "UserPreferencesPathAssistantCollapsed": false,
            "UserPreferencesPipelineViewHideHelpPopover": false,
            "UserPreferencesPreviewCustomTheme": false,
            "UserPreferencesPreviewLightning": false,
            "UserPreferencesRecordHomeReservedWTShown": false,
            "UserPreferencesRecordHomeSectionCollapseWTShown": false,
            "UserPreferencesReminderSoundOff": false,
            "UserPreferencesShowCityToExternalUsers": false,
            "UserPreferencesShowCityToGuestUsers": false,
            "UserPreferencesShowCountryToExternalUsers": false,
            "UserPreferencesShowCountryToGuestUsers": false,
            "UserPreferencesShowEmailToExternalUsers": false,
            "UserPreferencesShowEmailToGuestUsers": false,
            "UserPreferencesShowFaxToExternalUsers": false,
            "UserPreferencesShowFaxToGuestUsers": false,
            "UserPreferencesShowManagerToExternalUsers": false,
            "UserPreferencesShowManagerToGuestUsers": false,
            "UserPreferencesShowMobilePhoneToExternalUsers": false,
            "UserPreferencesShowMobilePhoneToGuestUsers": false,
            "UserPreferencesShowPostalCodeToExternalUsers": false,
            "UserPreferencesShowPostalCodeToGuestUsers": false,
            "UserPreferencesShowProfilePicToGuestUsers": false,
            "UserPreferencesShowStateToExternalUsers": false,
            "UserPreferencesShowStateToGuestUsers": false,
            "UserPreferencesShowStreetAddressToExternalUsers": false,
            "UserPreferencesShowStreetAddressToGuestUsers": false,
            "UserPreferencesShowTitleToExternalUsers": true,
            "UserPreferencesShowTitleToGuestUsers": false,
            "UserPreferencesShowWorkPhoneToExternalUsers": false,
            "UserPreferencesShowWorkPhoneToGuestUsers": false,
            "UserPreferencesSortFeedByComment": true,
            "UserPreferencesSuppressEventSFXReminders": false,
            "UserPreferencesSuppressTaskSFXReminders": false,
            "UserPreferencesTaskRemindersCheckboxDefault": false,
            "UserPreferencesUserDebugModePref": false,
            "UserReportCount__c": 1,
            "UserRole1__c": "Palo Alto Networks (TEST ACCT) Customer User",
            "UserRoleId": "00E70000000lfYIEAY",
            "UserType": "PowerCustomerSuccess",
            "UserTypebyProfile__c": "PowerCustomerSuccess",
            "User_Disabled_By__c": "svc-oktasalesforce@paloaltonetworks.com.sit",
            "User_Email_Signature__c": null,
            "User_has_AVP__c": false,
            "Username": "testdemisto@pancustportal.com.sit",
            "amorgan__Channel__c": null,
            "attributes": {
                "type": "User",
                "url": "/services/data/v44.0/sobjects/User/0050m000003K9VAAA0"
            },
            "ccrz__CC_CurrencyCode__c": null,
            "ccrz__CompanyType__c": null,
            "ccrz__ContactTypeRole__c": "Researcher/Post Doc",
            "ccrz__DataId__c": null,
            "ccrz__Tax_Exempt__c": false,
            "ccrz__User_Industry__c": "Academic research",
            "ccrz__User_Salutation__c": "Mr",
            "dfsle__CanManageAccount__c": false,
            "dfsle__Username__c": null,
            "dsfs__DSProSFUsername__c": null,
            "ltnadptn__Can_Use_Lightning__c": false,
            "ltnadptn__Using_Lightning__c": false,
            "pandb_account_id__c": null,
            "partner_account_id__c": "0017000000dN0hP",
            "recalculate_approval_manager__c": false,
            "sked__skeduloUserType__c": null,
            "sub_district__c": null,
            "zkmulti__EncryptedFedExEndUserKey__c": null,
            "zkmulti__EncryptedFedExEndUserPassword__c": null,
            "zkmulti__FedExEndUserKey__c": null,
            "zkmulti__FedExEndUserPassword__c": null,
            "zkmulti__FedExRegisteredPreference__c": null,
            "zkmulti__Registered_Preference__c": null,
            "zkmulti__UserCredentialsEncrypted__c": false
        },
        "email": "TestID@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "0050m000003K9VAAA0",
        "instanceName": "Salesforce",
        "success": true,
        "username": "testdemisto@pancustportal.com.sit"
    }
}
```

#### Human Readable Output

>### Get Salesforce User:
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| Salesforce IT Admin | Salesforce | true | false | 0050m000003K9VAAA0 | testdemisto@pancustportal.com.sit | TestID@paloaltonetworks.com | attributes: {"type": "User", "url": "/services/data/v44.0/sobjects/User/0050m000003K9VAAA0"}<br/>Id: 0050m000003K9VAAA0<br/>Username: testdemisto@pancustportal.com.sit<br/>LastName: Testing<br/>FirstName: Demisto<br/>Name: Demisto Testing<br/>CompanyName: null<br/>Division: null<br/>Department: null<br/>Title: null<br/>Street: null<br/>City: null<br/>State: null<br/>PostalCode: null<br/>Country: null<br/>Latitude: null<br/>Longitude: null<br/>GeocodeAccuracy: null<br/>Address: null<br/>Email: TestID@paloaltonetworks.com<br/>EmailPreferencesAutoBcc: true<br/>EmailPreferencesAutoBccStayInTouch: false<br/>EmailPreferencesStayInTouchReminder: true<br/>SenderEmail: null<br/>SenderName: null<br/>Signature: null<br/>StayInTouchSubject: null<br/>StayInTouchSignature: null<br/>StayInTouchNote: null<br/>Phone: null<br/>Fax: null<br/>MobilePhone: null<br/>Alias: dtest<br/>CommunityNickname: User15943166525412354768<br/>BadgeText: Customer<br/>IsActive: false<br/>TimeZoneSidKey: America/Los_Angeles<br/>UserRoleId: 00E70000000lfYIEAY<br/>LocaleSidKey: en_US<br/>ReceivesInfoEmails: false<br/>ReceivesAdminInfoEmails: false<br/>EmailEncodingKey: ISO-8859-1<br/>ProfileId: 00e70000000zseOAAQ<br/>UserType: PowerCustomerSuccess<br/>LanguageLocaleKey: en_US<br/>EmployeeNumber: null<br/>DelegatedApproverId: null<br/>ManagerId: null<br/>LastLoginDate: null<br/>LastPasswordChangeDate: null<br/>CreatedDate: 2020-07-09T17:44:12.000+0000<br/>CreatedById: 0050g000005sSA2AAM<br/>LastModifiedDate: 2020-08-11T15:55:08.000+0000<br/>LastModifiedById: 0050g000005sSA2AAM<br/>SystemModstamp: 2020-08-11T15:55:08.000+0000<br/>OfflineTrialExpirationDate: null<br/>OfflinePdaTrialExpirationDate: null<br/>UserPermissionsMarketingUser: false<br/>UserPermissionsOfflineUser: false<br/>UserPermissionsAvantgoUser: false<br/>UserPermissionsCallCenterAutoLogin: false<br/>UserPermissionsMobileUser: false<br/>UserPermissionsSFContentUser: false<br/>UserPermissionsKnowledgeUser: false<br/>UserPermissionsInteractionUser: false<br/>UserPermissionsSupportUser: false<br/>UserPermissionsChatterAnswersUser: false<br/>ForecastEnabled: false<br/>UserPreferencesActivityRemindersPopup: false<br/>UserPreferencesEventRemindersCheckboxDefault: false<br/>UserPreferencesTaskRemindersCheckboxDefault: false<br/>UserPreferencesReminderSoundOff: false<br/>UserPreferencesDisableAllFeedsEmail: false<br/>UserPreferencesDisableFollowersEmail: false<br/>UserPreferencesDisableProfilePostEmail: false<br/>UserPreferencesDisableChangeCommentEmail: false<br/>UserPreferencesDisableLaterCommentEmail: false<br/>UserPreferencesDisProfPostCommentEmail: false<br/>UserPreferencesContentNoEmail: false<br/>UserPreferencesContentEmailAsAndWhen: false<br/>UserPreferencesApexPagesDeveloperMode: false<br/>UserPreferencesHideCSNGetChatterMobileTask: false<br/>UserPreferencesDisableMentionsPostEmail: false<br/>UserPreferencesDisMentionsCommentEmail: false<br/>UserPreferencesHideCSNDesktopTask: false<br/>UserPreferencesHideChatterOnboardingSplash: false<br/>UserPreferencesHideSecondChatterOnboardingSplash: false<br/>UserPreferencesDisCommentAfterLikeEmail: false<br/>UserPreferencesDisableLikeEmail: true<br/>UserPreferencesSortFeedByComment: true<br/>UserPreferencesDisableMessageEmail: false<br/>UserPreferencesDisableBookmarkEmail: false<br/>UserPreferencesDisableSharePostEmail: false<br/>UserPreferencesEnableAutoSubForFeeds: false<br/>UserPreferencesDisableFileShareNotificationsForApi: false<br/>UserPreferencesShowTitleToExternalUsers: true<br/>UserPreferencesShowManagerToExternalUsers: false<br/>UserPreferencesShowEmailToExternalUsers: false<br/>UserPreferencesShowWorkPhoneToExternalUsers: false<br/>UserPreferencesShowMobilePhoneToExternalUsers: false<br/>UserPreferencesShowFaxToExternalUsers: false<br/>UserPreferencesShowStreetAddressToExternalUsers: false<br/>UserPreferencesShowCityToExternalUsers: false<br/>UserPreferencesShowStateToExternalUsers: false<br/>UserPreferencesShowPostalCodeToExternalUsers: false<br/>UserPreferencesShowCountryToExternalUsers: false<br/>UserPreferencesShowProfilePicToGuestUsers: false<br/>UserPreferencesShowTitleToGuestUsers: false<br/>UserPreferencesShowCityToGuestUsers: false<br/>UserPreferencesShowStateToGuestUsers: false<br/>UserPreferencesShowPostalCodeToGuestUsers: false<br/>UserPreferencesShowCountryToGuestUsers: false<br/>UserPreferencesPipelineViewHideHelpPopover: false<br/>UserPreferencesHideS1BrowserUI: false<br/>UserPreferencesDisableEndorsementEmail: false<br/>UserPreferencesPathAssistantCollapsed: false<br/>UserPreferencesCacheDiagnostics: false<br/>UserPreferencesShowEmailToGuestUsers: false<br/>UserPreferencesShowManagerToGuestUsers: false<br/>UserPreferencesShowWorkPhoneToGuestUsers: false<br/>UserPreferencesShowMobilePhoneToGuestUsers: false<br/>UserPreferencesShowFaxToGuestUsers: false<br/>UserPreferencesShowStreetAddressToGuestUsers: false<br/>UserPreferencesLightningExperiencePreferred: true<br/>UserPreferencesPreviewLightning: false<br/>UserPreferencesHideEndUserOnboardingAssistantModal: false<br/>UserPreferencesHideLightningMigrationModal: false<br/>UserPreferencesHideSfxWelcomeMat: true<br/>UserPreferencesHideBiggerPhotoCallout: false<br/>UserPreferencesGlobalNavBarWTShown: false<br/>UserPreferencesGlobalNavGridMenuWTShown: false<br/>UserPreferencesCreateLEXAppsWTShown: false<br/>UserPreferencesFavoritesWTShown: false<br/>UserPreferencesRecordHomeSectionCollapseWTShown: false<br/>UserPreferencesRecordHomeReservedWTShown: false<br/>UserPreferencesFavoritesShowTopFavorites: false<br/>UserPreferencesExcludeMailAppAttachments: false<br/>UserPreferencesSuppressTaskSFXReminders: false<br/>UserPreferencesSuppressEventSFXReminders: false<br/>UserPreferencesPreviewCustomTheme: false<br/>UserPreferencesHasCelebrationBadge: false<br/>UserPreferencesUserDebugModePref: false<br/>UserPreferencesNewLightningReportRunPageEnabled: false<br/>ContactId: 0030m00000XWAwYAAX<br/>AccountId: 0017000000dN0hPAAS<br/>CallCenterId: null<br/>Extension: null<br/>PortalRole: null<br/>IsPortalEnabled: true<br/>IsPortalSelfRegistered: false<br/>FederationIdentifier: null<br/>AboutMe: null<br/>FullPhotoUrl: https://paloaltonetworks--sit--c.cs65.content.force.com/profilephoto/005/F<br/>SmallPhotoUrl: https://paloaltonetworks--sit--c.cs65.content.force.com/profilephoto/005/T<br/>IsExtIndicatorVisible: false<br/>OutOfOfficeMessage: <br/>MediumPhotoUrl: https://paloaltonetworks--sit--c.cs65.content.force.com/profilephoto/005/M<br/>DigestFrequency: N<br/>DefaultGroupNotificationFrequency: D<br/>LastViewedDate: 2020-08-11T15:55:04.000+0000<br/>LastReferencedDate: 2020-08-11T15:55:04.000+0000<br/>BannerPhotoUrl: /profilephoto/005/B<br/>SmallBannerPhotoUrl: /profilephoto/005/D<br/>MediumBannerPhotoUrl: /profilephoto/005/E<br/>IsProfilePhotoActive: false<br/>IndividualId: null<br/>Approver__c: null<br/>Alias_Email__c: null<br/>Theatre__c: null<br/>Terminate_Date__c: 2020-08-04<br/>Sales_Coverage__c: null<br/>Lead_Assignment__c: null<br/>PAN_Internal_User__c: No<br/>My_Sales_Level__c: Non-Sales<br/>Managers_Sales_Level__c: null<br/>Out_of_Office__c: false<br/>pandb_account_id__c: null<br/>amorgan__Channel__c: null<br/>Do_not_show_this_message_again__c: false<br/>ISO_Country__c: null<br/>Region__c: null<br/>Support_Engineer_Location__c: null<br/>District__c: null<br/>Active_LeadAssignment__c: false<br/>RoundRobin_LeadCountries__c: null<br/>RoundRobin_LeadCountriesEMEA__c: null<br/>RoundRobin_LeadCountriesAmericas__c: null<br/>RoundRobin_LeadCountriesROW__c: null<br/>Employee_Code__c: 0050m000003K9VAAA0<br/>GraveYard_Objects__c: null<br/>Search_GraveYardObjects__c: false<br/>UserTypebyProfile__c: PowerCustomerSuccess<br/>TMBDR__c: false<br/>TMCBM__c: false<br/>TMCSR__c: false<br/>TMCSSR__c: false<br/>TMGAM__c: false<br/>TMICBM__c: false<br/>TMMAM__c: false<br/>TMPSR__c: false<br/>TMRSM__c: false<br/>TMSBDR__c: false<br/>TMSE__c: false<br/>TMSRR__c: false<br/>Email_Signature__c: null<br/>Network_ID__c: null<br/>Manager__c: null<br/>Employee_Number__c: null<br/>UserRole1__c: Palo Alto Networks (TEST ACCT) Customer User<br/>User_Disabled_By__c: svc-oktasalesforce@paloaltonetworks.com.sit<br/>Sales_Specialization__c: null<br/>CPQ_User_Name__c: null<br/>Create_CPQ_User__c: false<br/>Manager_Username__c: null<br/>M_A_Id__c: null<br/>M_A_Source__c: null<br/>User_Email_Signature__c: null<br/>Five9__Five9AgentId__c: null<br/>Recalculate_Partner_Sharing__c: false<br/>FCRM__FCR_Email_Notification_Delegate__c: null<br/>FCRM__FCR_User_Notification_Delegate__c: null<br/>SOX_Notes__c: Enabled by XSOAR<br/>Area__c: null<br/>Segment__c: null<br/>User_has_AVP__c: false<br/>partner_account_id__c: 0017000000dN0hP<br/>CPQUserMessage__c: null<br/>Date_Deactivated__c: 2020-08-11T15:55:08.000+0000<br/>My_Backup__c: null<br/>My_Return_Date__c: null<br/>My_Vacation_Start_Date__c: null<br/>UserReportCount__c: 1.0<br/>PANWEntity__c: null<br/>Full_Name__c: Demisto Testing<br/>Direct_Manager__c: null<br/>ltnadptn__Can_Use_Lightning__c: false<br/>ltnadptn__Using_Lightning__c: false<br/>DNE__c: false<br/>Direct_Manager_Sales_Level__c: null<br/>Outreach_Id__c: null<br/>sub_district__c: null<br/>Five9__Five9Agent_Login_TimeStamp__c: null<br/>Apttus_Approval__Approval_Level__c: null<br/>Apttus_Approval__Next_Level_Approver__c: null<br/>SBQQ__DefaultProductLookupTab__c: Guided Selling<br/>SBQQ__DiagnosticToolEnabled__c: false<br/>SBQQ__OutputFormatChangeAllowed__c: false<br/>SBQQ__ProductSortPreference__c: null<br/>SBQQ__ResetProductLookup__c: false<br/>SBQQ__Theme__c: null<br/>dsfs__DSProSFUsername__c: null<br/>dfsle__CanManageAccount__c: false<br/>dfsle__Username__c: null<br/>ccrz__CC_CurrencyCode__c: null<br/>ccrz__CompanyType__c: null<br/>ccrz__ContactTypeRole__c: Researcher/Post Doc<br/>ccrz__DataId__c: null<br/>ccrz__Tax_Exempt__c: false<br/>ccrz__User_Industry__c: Academic research<br/>ccrz__User_Salutation__c: Mr<br/>IsMarketplace__c: false<br/>SSO_UID__c: null<br/>Bunchball_Id__c: null<br/>Calculated_Bunchball_ID__c: testdemisto@pancustportal.com.sit<br/>Exclude_Approval_Mgr_from_Workday_Update__c: false<br/>recalculate_approval_manager__c: false<br/>Exclude_from_Anaplan_Update__c: false<br/>Anaplan_Role__c: null<br/>zkmulti__EncryptedFedExEndUserKey__c: null<br/>zkmulti__EncryptedFedExEndUserPassword__c: null<br/>zkmulti__FedExEndUserKey__c: null<br/>zkmulti__FedExEndUserPassword__c: null<br/>zkmulti__FedExRegisteredPreference__c: null<br/>zkmulti__Registered_Preference__c: null<br/>zkmulti__UserCredentialsEncrypted__c: false<br/>sked__skeduloUserType__c: null<br/>IsUSC__c: false |


### create-user
***
Creates a user


#### Base Command

`create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON formatt | Required | 
| customMapping | An optional custom mapping that takes custom values in the SCIM data into the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| CreateUser | Unknown | Command context path | 
| CreateUser.brand | String | Name of the Integration | 
| CreateUser.instanceName | String | Name of the instance used for testing | 
| CreateUser.success | Boolean | Status of the result. Can be true or false. | 
| CreateUser.active | Boolean | Gives the active status of user. Can be true of false.  | 
| CreateUser.id | String | Value of id created, returns only if response is success | 
| CreateUser.username | String | Value of username created, returns only if response is success | 
| CreateUser.email | String | Value of email ID passed as argument | 
| CreateUser.errorCode | Number | HTTP response code other than 200 \(if there is error in response\) | 
| CreateUser.errorMessage | String | Reason why the API is failed | 
| CreateUser.details | Unknown | Gives the raw response from API | 


#### Command Example
```!create-user scim={"userName":"testdemisto23@pancustportal.com.sit","name":{"familyName":"Test","givenName":"Demisto"},"emails":[{"type":"work","primary":true,"value":"demistoTestID@paloaltonetworks.com"}],"urn:scim:schemas:extension:custom:1.0:user":{"Alias":"dtest","TimeZoneSidKey":"America/Los_Angeles","LocaleSidKey":"en_US","EmailEncodingKey":"ISO-8859-1","ProfileId":"00e70000000opnNAAQ","LanguageLocaleKey":"en_US","Department":"IT"}} customMapping={"Alias":"Alias","TimeZoneSidKey":"TimeZoneSidKey","LocaleSidKey":"LocaleSidKey","EmailEncodingKey":"EmailEncodingKey","ProfileId":"ProfileId","LanguageLocaleKey":"LanguageLocaleKey","Department":"Department"}  using=Salesforce```

#### Context Example
```
{
    "CreateUser": {
        "active": true,
        "brand": "Salesforce IT Admin",
        "details": {
            "errors": [],
            "id": "0050m000003Mlg3AAC",
            "success": true
        },
        "email": "demistoTestID@paloaltonetworks.com",
        "errorCode": null,
        "errorMessage": null,
        "id": "0050m000003Mlg3AAC",
        "instanceName": "Salesforce",
        "success": true,
        "username": "testdemisto23@pancustportal.com.sit"
    }
}
```

#### Human Readable Output

>### Create Salesforce User:
>|brand|instanceName|success|active|id|username|email|details|
>|---|---|---|---|---|---|---|---|
>| Salesforce IT Admin | Salesforce | true | true | 0050m000003Mlg3AAC | testdemisto23@pancustportal.com.sit | demistoTestID@paloaltonetworks.com | id: 0050m000003Mlg3AAC<br/>success: true<br/>errors:  |


### update-user
***
Update a user


#### Base Command

`update-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| oldScim | Old SCIM content in JSON format | Required | 
| newScim | New SCIM content in JSON format | Required | 
| customMapping | An optional custom mapping that takes custom values in the SCIM data into the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| UpdateUser | Unknown | Command context path | 
| UpdateUser.brand | String | Name of the Integration | 
| UpdateUser.instanceName | String | Name of the instance used for testing | 
| UpdateUser.success | Boolean | Status of the result. Can be true or false. | 
| UpdateUser.active | Boolean | Gives the active status of user. Can be true of false.  | 
| UpdateUser.id | String | Value of id passed as argument | 
| UpdateUser.username | String | Value of username passed as argument | 
| UpdateUser.email | String | Value of email ID passed as argument | 
| UpdateUser.errorCode | String | HTTP response code other than 200 \(if there is error in response\) | 
| UpdateUser.errorMessage | String |  Reason why the API is failed | 
| UpdateUser.details | String | Gives the raw response from API | 


#### Command Example
```!update-user oldScim={"id":"0050m000003K9VAAA0"} newScim={"name":{"givenName":"Demisto"}} using=Salesforce```

#### Context Example
```
{
    "UpdateUser": {
        "active": true,
        "brand": "Salesforce IT Admin",
        "details": null,
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "0050m000003K9VAAA0",
        "instanceName": "Salesforce",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Update Salesforce User:
>|brand|instanceName|success|active|id|
>|---|---|---|---|---|
>| Salesforce IT Admin | Salesforce | true | true | 0050m000003K9VAAA0 |


### salesforce-assign-permission-set
***
Assign Permission set for user


#### Base Command

`salesforce-assign-permission-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID | Required | 
| permission_set_id | Permission set ID of tthe user | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesforceAssignPermissionSet | unknown | Command context path | 
| SalesforceAssignPermissionSet.success | boolean | Status of the result. Can be true or false. | 
| SalesforceAssignPermissionSet.PermissionSetAssign.id | string | Permission set assignment id created | 
| SalesforceAssignPermissionSet.errorCode | string | Error code from API, displayed in case of failure | 
| SalesforceAssignPermissionSet.errorMessage | string | Error message from API, displayed in case of failure | 


#### Command Example
```!salesforce-assign-permission-set user_id="0050m000003MAxCAAW" permission_set_id="0PS0m000000IuIrGAK" using=Salesforce```

#### Context Example
```
{
    "SalesforceAssignPermissionSet": {
        "PermissionSetAssign": {
            "id": "0Pa0m000003bH9HCAU"
        },
        "success": true
    }
}
```

#### Human Readable Output

>### Assign Permission Set:
>|success|PermissionSetAssign|
>|---|---|
>| true | id: 0Pa0m000003bH9HCAU |


### salesforce-get-assigned-permission-set
***
Get the assigned permission set


#### Base Command

`salesforce-get-assigned-permission-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesforceGetAssignedPermissionSet | unknown | Command context path | 
| SalesforceGetAssignedPermissionSet.success | boolean | Status of the result. Can be true or false. | 
| SalesforceGetAssignedPermissionSet.PermissionSetAssignments.attributes | string | Attributes field gives the information about the type and url of the field fetched | 
| SalesforceGetAssignedPermissionSet.PermissionSetAssignments.AssigneeId | string | User ID passed as input | 
| SalesforceGetAssignedPermissionSet.PermissionSetAssignments.Id | string | Permission Set Assignment Id created | 
| SalesforceGetAssignedPermissionSet.errorCode | string | Error code from API, displayed in case of failure | 
| SalesforceGetAssignedPermissionSet.errorMessage | string | Error message from API, displayed in case of failure | 


#### Command Example
```!salesforce-get-assigned-permission-set user_id="0050m000003MAxCAAW" using=Salesforce```

#### Context Example
```
{
    "SalesforceGetAssignedPermissionSet": {
        "PermissionSetAssignments": [
            {
                "AssigneeId": "0050m000003MAxCAAW",
                "Id": "0Pa0m000003bH9HCAU",
                "PermissionSetId": "0PS0m000000IuIrGAK",
                "attributes": {
                    "type": "PermissionSetAssignment",
                    "url": "/services/data/v44.0/sobjects/PermissionSetAssignment/0Pa0m000003bH9HCAU"
                }
            },
            {
                "AssigneeId": "0050m000003MAxCAAW",
                "Id": "0Pa0m000003AzzVCAS",
                "PermissionSetId": "0PS70000000MlvWGAS",
                "attributes": {
                    "type": "PermissionSetAssignment",
                    "url": "/services/data/v44.0/sobjects/PermissionSetAssignment/0Pa0m000003AzzVCAS"
                }
            }
        ],
        "success": true
    }
}
```

#### Human Readable Output

>### Get Assigned Permission Set:
>|success|PermissionSetAssignments|
>|---|---|
>| true | {'attributes': {'type': 'PermissionSetAssignment', 'url': '/services/data/v44.0/sobjects/PermissionSetAssignment/0Pa0m000003bH9HCAU'}, 'AssigneeId': '0050m000003MAxCAAW', 'Id': '0Pa0m000003bH9HCAU', 'PermissionSetId': '0PS0m000000IuIrGAK'},<br/>{'attributes': {'type': 'PermissionSetAssignment', 'url': '/services/data/v44.0/sobjects/PermissionSetAssignment/0Pa0m000003AzzVCAS'}, 'AssigneeId': '0050m000003MAxCAAW', 'Id': '0Pa0m000003AzzVCAS', 'PermissionSetId': '0PS70000000MlvWGAS'} |


### salesforce-delete-assigned-permission-set
***
To Delete Assigned Permission Set


#### Base Command

`salesforce-delete-assigned-permission-set`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| permission_set_assignment_id | Id in PermissionSetAssignment object. PermissionSetAssignment - Represent the association between a User and a PermissionSet. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesforceDeleteAssignedPermissionSet | unknown | Command context path | 
| SalesforceDeleteAssignedPermissionSet.success | boolean | Status of the result. Can be true or false. | 
| SalesforceDeleteAssignedPermissionSet.errorCode | number | Error code from API, displayed in case of failure | 
| SalesforceDeleteAssignedPermissionSet.errorMessage | string | Error message from API, displayed in case of failure | 


#### Command Example
```!salesforce-delete-assigned-permission-set permission_set_assignment_id="0Pa0m000003bH2ECAU" using=Salesforce```

#### Context Example
```
{
    "SalesforceDeleteAssignedPermissionSet": {
        "success": true
    }
}
```

#### Human Readable Output

>### Delete Assigned Permission Set License:
>|success|
>|---|
>| true |


### salesforce-freeze-user-account
***
Freeze the user account


#### Base Command

`salesforce-freeze-user-account`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_login_id | Id in UserLogin object. UserLogin - Represents the settings that affect a user’s ability to log into an organization. To access this object, you need the UserPermissions.ManageUsers permission. For more details Please refer "https://developer.salesforce.com/docs/atlas.en-us.api.meta/api/sforce_api_objects_userlogin.htm" | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesforceFreezeUserAccount | unknown | Command context path | 
| SalesforceFreezeUserAccount.success | boolean | Status of the result. Can be true or false. | 
| SalesforceFreezeUserAccount.errorCode | number | Error code from API, displayed in case of failure | 
| SalesforceFreezeUserAccount.errorMessage | string | Error message from API, displayed in case of failure | 


#### Command Example
```!salesforce-freeze-user-account user_login_id="0Yw0m000002T4lqCAC" using=Salesforce```

#### Context Example
```
{
    "SalesforceFreezeUserAccount": {
        "success": true
    }
}
```

#### Human Readable Output

>### Freeze User Account
>|success|
>|---|
>| true |


### salesforce-unfreeze-user-account
***
Unfreeze User Account


#### Base Command

`salesforce-unfreeze-user-account`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_login_id | Id in UserLogin object. UserLogin - Represents the settings that affect a user’s ability to log into an organization. To access this object, you need the UserPermissions.ManageUsers permission. For more details Please refer "https://developer.salesforce.com/docs/atlas.en-us.api.meta/api/sforce_api_objects_userlogin.htm" | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesforceUnfreezeUserAccount | unknown | Command context path | 
| SalesforceUnfreezeUserAccount.success | boolean | Status of the result. Can be true or false. | 
| SalesforceUnfreezeUserAccount.errorCode | number | Error code from API, displayed in case of failure | 
| SalesforceUnfreezeUserAccount.errorMessage | string | Error message from API, displayed in case of failure | 


#### Command Example
```!salesforce-unfreeze-user-account user_login_id="0Yw0m000002T4lqCAC" using=Salesforce```

#### Context Example
```
{
    "SalesforceUnfreezeUserAccount": {
        "success": true
    }
}
```

#### Human Readable Output

>### Unfreeze User Account
>|success|
>|---|
>| true |


### salesforce-get-user-isfrozen-status
***
Get the user frozen status


#### Base Command

`salesforce-get-user-isfrozen-status`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesforceGetUserIsfrozenStatus | unknown | Command context path | 
| SalesforceGetUserIsfrozenStatus.success | boolean | Status of the result. Can be true or false. | 
| SalesforceGetUserIsfrozenStatus.UserIsfrozenStatus.attributes | string | Attributes field gives the information about the type,  url of the field fetched. | 
| SalesforceGetUserIsfrozenStatus.UserIsfrozenStatus.Id | string | Id in UserLogin object. UserLogin \- Represents the settings that affect a user’s ability to log into an organization. To access this object, you need the UserPermissions.ManageUsers permission. For more details Please refer "https://developer.salesforce.com/docs/atlas.en\-us.api.meta/api/sforce\_api\_objects\_userlogin.htm" | 
| SalesforceGetUserIsfrozenStatus.UserIsfrozenStatus.IsFrozen | boolean | Whether the User account is in frozen state. Can be true or false | 
| SalesforceGetUserIsfrozenStatus.errorCode | string | Error code from API, displayed in case of failure | 
| SalesforceGetUserIsfrozenStatus.errorMessage | string | Error message from API, displayed in case of failure | 


#### Command Example
```!salesforce-get-user-isfrozen-status user_id="0050m000003MAxCAAW" using=Salesforce```

#### Context Example
```
{
    "SalesforceGetUserIsfrozenStatus": {
        "UserIsfrozenStatus": [
            {
                "Id": "0Yw0m000002T4lqCAC",
                "IsFrozen": false,
                "attributes": {
                    "type": "UserLogin",
                    "url": "/services/data/v44.0/sobjects/UserLogin/0Yw0m000002T4lqCAC"
                }
            }
        ],
        "success": true
    }
}
```

#### Human Readable Output

>### Get frozen user account id:
>|success|UserIsfrozenStatus|
>|---|---|
>| true | {'attributes': {'type': 'UserLogin', 'url': '/services/data/v44.0/sobjects/UserLogin/0Yw0m000002T4lqCAC'}, 'Id': '0Yw0m000002T4lqCAC', 'IsFrozen': False} |


### salesforce-assign-permission-set-license
***
Assign permission set license


#### Base Command

`salesforce-assign-permission-set-license`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID | Required | 
| permission_set_license_id | Permission set license id | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesforceAssignPermissionSetLicense | unknown | Command context path | 
| SalesforceAssignPermissionSetLicense.success | boolean | Status of the result. Can be true or false. | 
| SalesforceAssignPermissionSetLicense.PermissionSetLicenseAssign.id | string | Permission set assignment license id created | 
| SalesforceAssignPermissionSetLicense.errorCode | string | Error code from API, displayed in case of failure | 
| SalesforceAssignPermissionSetLicense.errorMessage | string | Error message from API, displayed in case of failure | 


#### Command Example
```!salesforce-assign-permission-set-license user_id="0050m000003MAxCAAW" permission_set_license_id="0PL0g0000008QVEGA2"  using=Salesforce```

#### Context Example
```
{
    "SalesforceAssignPermissionSetLicense": {
        "PermissionSetLicenseAssign": {
            "id": "2LA0m0000005pOSGAY"
        },
        "success": true
    }
}
```

#### Human Readable Output

>### Assign Permission Set License:
>|success|PermissionSetLicenseAssign|
>|---|---|
>| true | id: 2LA0m0000005pOSGAY |


### salesforce-get-assigned-permission-set-license
***
Get assigned permission set license


#### Base Command

`salesforce-get-assigned-permission-set-license`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesforceGetAssignedPermissionSetLicense | unknown | Command context path | 
| SalesforceGetAssignedPermissionSetLicense.success | boolean | Status of the result. Can be true or false. | 
| SalesforceGetAssignedPermissionSetLicense.PermissionSetLicenseAssignments.attributes | string | Attributes field gives the information about the type and url of the field fetched | 
| SalesforceGetAssignedPermissionSetLicense.PermissionSetLicenseAssignments.AssigneeId | string | User ID passed as input | 
| SalesforceGetAssignedPermissionSetLicense.PermissionSetLicenseAssignments.Id | string | Permission Set License Assignments Id assigned for given user ID | 
| SalesforceGetAssignedPermissionSetLicense.errorCode | string | Error code from API, displayed in case of failure | 
| SalesforceGetAssignedPermissionSetLicense.errorMessage | string | Error message from API, displayed in case of failure | 


#### Command Example
```!salesforce-get-assigned-permission-set-license user_id="0050m000003MAxCAAW" using=Salesforce```

#### Context Example
```
{
    "SalesforceGetAssignedPermissionSetLicense": {
        "PermissionSetLicenseAssignments": [
            {
                "AssigneeId": "0050m000003MAxCAAW",
                "Id": "2LA0m0000005pOSGAY",
                "attributes": {
                    "type": "PermissionSetLicenseAssign",
                    "url": "/services/data/v44.0/sobjects/PermissionSetLicenseAssign/2LA0m0000005pOSGAY"
                }
            }
        ],
        "success": true
    }
}
```

#### Human Readable Output

>### Salesforce Get Assigned Permission Set License:
>|success|PermissionSetLicenseAssignments|
>|---|---|
>| true | {'attributes': {'type': 'PermissionSetLicenseAssign', 'url': '/services/data/v44.0/sobjects/PermissionSetLicenseAssign/2LA0m0000005pOSGAY'}, 'AssigneeId': '0050m000003MAxCAAW', 'Id': '2LA0m0000005pOSGAY'} |


### salesforce-delete-assigned-permission-set-license
***
Delete assigned permission set license


#### Base Command

`salesforce-delete-assigned-permission-set-license`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| permission_set_assignment_license_id | Id in PermissionSetLicenseAssign object. PermissionSetLicenseAssign - Represents the association between a User and a PermissionSetLicense | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesforceDeleteAssignedPermissionSetLicense | unknown | Command context path | 
| SalesforceDeleteAssignedPermissionSetLicense.success | boolean | Status of the result. Can be true or false. | 
| SalesforceDeleteAssignedPermissionSetLicense.errorCode | string | Error code from API, displayed in case of failure | 
| SalesforceDeleteAssignedPermissionSetLicense.errorMessage | string | Error message from API, displayed in case of failure | 


#### Command Example
```!salesforce-delete-assigned-permission-set-license permission_set_assignment_license_id="2LA0m0000005pONGAY" using=Salesforce```

#### Context Example
```
{
    "SalesforceDeleteAssignedPermissionSetLicense": {
        "success": true
    }
}
```

#### Human Readable Output

>### Delete Assigned Permission Set License:
>|success|
>|---|
>| true |


### salesforce-assign-package-license
***
Assign Package License


#### Base Command

`salesforce-assign-package-license`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID | Required | 
| package_license_id | Package License ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesforceAssignPackageLicense | unknown | Command context path | 
| SalesforceAssignPackageLicense.success | boolean | Status of the result. Can be true or false. | 
| SalesforceAssignPackageLicense.PackageLicenseAssign.id | boolean | Package License Assign Id created | 
| SalesforceAssignPackageLicense.errorCode | number | Error code from API, displayed in case of failure | 
| SalesforceAssignPackageLicense.errorMessage | string | Error message from API, displayed in case of failure | 


#### Command Example
```!salesforce-assign-package-license user_id="0050m000003K9VAAA0" package_license_id="05070000000PHmCAAW" using=Salesforce```

#### Context Example
```
{
    "SalesforceAssignPackageLicense": {
        "PackageLicenseAssign": {
            "id": "0510m00000008psAAA"
        },
        "success": true
    }
}
```

#### Human Readable Output

>### Assign Package License:
>|success|PackageLicenseAssign|
>|---|---|
>| true | id: 0510m00000008psAAA |


### salesforce-get-assigned-package-license
***
Get Assigned Package License


#### Base Command

`salesforce-get-assigned-package-license`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_id | User ID | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesforceGetAssignedPackageLicense | unknown | Command context path | 
| SalesforceGetAssignedPackageLicense.success | boolean | Status of the result. Can be true or false. | 
| SalesforceGetAssignedPackageLicense.PackageLicenseAssignments.attributes | boolean | Attributes field gives the information about the type and url of the field fetched | 
| SalesforceGetAssignedPackageLicense.PackageLicenseAssignments.AssigneeId | string | User ID passed as input | 
| SalesforceGetAssignedPackageLicense.PackageLicenseAssignments.Id | string | Package License Assignment ID  assigned for given user ID | 
| SalesforceGetAssignedPackageLicense.errorCode | number | Error code from API, displayed in case of failure | 
| SalesforceGetAssignedPackageLicense.errorMessage | string | Error message from API, displayed in case of failure | 


#### Command Example
```!salesforce-get-assigned-package-license user_id="0050m000003K9VAAA0" using=Salesforce```

#### Context Example
```
{
    "SalesforceGetAssignedPackageLicense": {
        "PackageLicenseAssignments": [
            {
                "Id": "0510m00000008psAAA",
                "UserId": "0050m000003K9VAAA0",
                "attributes": {
                    "type": "UserPackageLicense",
                    "url": "/services/data/v44.0/sobjects/UserPackageLicense/0510m00000008psAAA"
                }
            }
        ],
        "success": true
    }
}
```

#### Human Readable Output

>### Get Assigned Package License:
>|success|PackageLicenseAssignments|
>|---|---|
>| true | {'attributes': {'type': 'UserPackageLicense', 'url': '/services/data/v44.0/sobjects/UserPackageLicense/0510m00000008psAAA'}, 'Id': '0510m00000008psAAA', 'UserId': '0050m000003K9VAAA0'} |


### salesforce-delete-assigned-package-license
***
Delete Assigned Package License


#### Base Command

`salesforce-delete-assigned-package-license`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user_package_license_id | Id field in the UserPackageLicense object. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SalesforceDeleteAssignedPackageLicense | unknown | Command context path | 
| SalesforceDeleteAssignedPackageLicense.success | boolean | Status of the result. Can be true or false. | 
| SalesforceDeleteAssignedPackageLicense.errorCode | number | Error code from API, displayed in case of failure | 
| SalesforceDeleteAssignedPackageLicense.errorMessage | string | Error message from API, displayed in case of failure | 


#### Command Example
```!salesforce-delete-assigned-package-license user_package_license_id="0510m00000008pnAAA" using=Salesforce```

#### Context Example
```
{
    "SalesforceDeleteAssignedPackageLicense": {
        "success": true
    }
}
```

#### Human Readable Output

>### Delete Assigned Package License:
>|success|
>|---|
>| true |


### enable-user
***
Enable a disabled user


#### Base Command

`enable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required |


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| EnableUser | unknown | Command context path |
| EnableUser.brand | string | Name of the Integration |
| EnableUser.instanceName | string | Name the instance used for testing |
| EnableUser.success | boolean | Status of the result. Can be true or false. |
| EnableUser.active | boolean | Gives the active status of user. Can be true of false.  |
| EnableUser.id | string | Value of id passed as argument |
| EnableUser.username | string | Value of username passed as argument |
| EnableUser.email | string | Value of email ID passed as argument |
| EnableUser.errorCode | number | HTTP response code other than 200 \(if there is error in response\) |
| EnableUser.errorMessage | string | Reason why the API is failed |
| EnableUser.details | string | Gives the raw response from API in case of error |


#### Command Example
```!enable-user scim=`{"id":"0050m000003K9VAAA0","urn:scim:schemas:extension:custom:1.0:user":{"SOX_Notes__c":"Enabled by XSOAR"}}` customMapping=`{"SOX_Notes__c":"SOX_Notes__c"}` using=Salesforce```

#### Context Example
```
{
    "EnableUser": {
        "active": true,
        "brand": "Salesforce IT Admin",
        "details": null,
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "0050m000003K9VAAA0",
        "instanceName": "Salesforce",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Enable Salesforce User:
>|brand|instanceName|success|active|id|
>|---|---|---|---|---|
>| Salesforce IT Admin | Salesforce | true | true | 0050m000003K9VAAA0 |


### disable-user
***
Disable a user


#### Base Command

`disable-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| scim | SCIM content in JSON format | Required | 
| customMapping | An optional custom mapping that takes custom values in the SCIM data into the integration. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DisableUser | unknown | Command context path | 
| DisableUser.brand | string | Name of the Integration | 
| DisableUser.instanceName | string | Name the instance used for testing | 
| DisableUser.success | boolean | Status of the result. Can be true or false. | 
| DisableUser.active | boolean | Gives the active status of user. Can be true of false.  | 
| DisableUser.id | string | Value of id passed as argument | 
| DisableUser.username | string | Value of username passed as argument | 
| DisableUser.email | string | Value of email ID passed as argument | 
| DisableUser.errorCode | number | HTTP response code other than 200 \(if there is error in response\) | 
| DisableUser.errorMessage | string | Reason why the API is failed | 
| DisableUser.details | string | Gives the raw response from API in case of error | 


#### Command Example
```!disable-user scim={"id":"0050m000003K9VAAA0","urn:scim:schemas:extension:custom:1.0:user":{"terminationDate":"2020-08-04"}} customMapping={"terminationDate":"Terminate_Date__c"} using=Salesforce```

#### Context Example
```
{
    "DisableUser": {
        "active": false,
        "brand": "Salesforce IT Admin",
        "details": null,
        "email": null,
        "errorCode": null,
        "errorMessage": null,
        "id": "0050m000003K9VAAA0",
        "instanceName": "Salesforce",
        "success": true,
        "username": null
    }
}
```

#### Human Readable Output

>### Disable Salesforce User:
>|brand|instanceName|success|active|id|
>|---|---|---|---|---|
>| Salesforce IT Admin | Salesforce | true | false | 0050m000003K9VAAA0 |

