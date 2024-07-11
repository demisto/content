Impartner is the fastest-growing, most award-winning channel management solution provider on the market.
This integration was integrated and tested with version v1 of [Impartner Objects API](https://prod.impartner.live/swagger/ui/index#/).

## Configure Impartner on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Impartner.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | API Key | The API Key to use for connection | True |
    | Trust any certificate (not secure) |  | False |

4. Click **Test** to validate the URLs, token, and connection.
5. to get API key, please reach out to Impartner contact
6. 
## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### impartner-get-account-list

***
Get account IDs from Impartner

#### Base Command

`impartner-get-account-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | query for searching accounts. | Optional | 
| fields | Comma separated list of fields to retrieve. | Optional | 
| filter | Optional where clause (eg, Field1 = Val1 and Field2 &gt; Val2). | Optional | 
| orderby | Comma separated list of fields to sort by. | Optional | 
| skip | Number of results to skip for pagination. | Optional | 
| take | Number of results to take for pagination. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Impartner.Account.list.count | String | Number of results returned | 
| Impartner.Account.list.entity | String | Type of entity returned | 
| Impartner.Account.list.results | Array | Type of entity returned | 
| Impartner.Account.list.results.id | String | ID of account | 
| Impartner.Account.list.success | Boolean | Whether result was successful | 

#### Command example
```!impartner-get-account-list```
#### Context Example
```json
{
    "Impartner": {
        "Accounts": {
            "List": {
                "count": 471,
                "entity": "Account",
                "results": [
                    {
                        "id": 1111
                    },
                    {
                        "id": 1112
                    },
                    {
                        "id": 1113
                    },
                    {
                        "id": 1114
                    },
                    {
                        "id": 1115
                    },
                    {
                        "id": 1116
                    },
                    {
                        "id": 1117
                    },
                    {
                        "id": 1118
                    },
                    {
                        "id": 1119
                    },
                    {
                        "id": 1120
                    }
                ]
            }
        }
    }
}
```

#### Human Readable Output

>### List of account ID's
>| id   |
>|------|
>| 1111 |
>| 1112 |
>| 1113 |
>| 1114 |
>| 1115 |
>| 1116 |
>| 1117 |
>| 1118 |
>| 1119 |
>| 1120 |


### impartner-get-account-id

***
Get account details from Impartner

#### Base Command

`impartner-get-account-id`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | id of Impartner account. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Impartner.Account.accountManagerId | Unknown | Test | 
| Impartner.Account.site | Unknown | Test | 
| Impartner.Account.faxAlternate | Unknown | Test | 
| Impartner.Account.phoneAlternate | Unknown | Test | 
| Impartner.Account.autoAssignTier | Boolean | Test | 
| Impartner.Account.autoAssignRegion | Boolean | Test | 
| Impartner.Account.comments | Unknown | Test | 
| Impartner.Account.convertedApplicantId | Unknown | Test | 
| Impartner.Account.created | Date | Test | 
| Impartner.Account.createdById | Number | Test | 
| Impartner.Account.crmAccountType | String | Test | 
| Impartner.Account.crmId | Unknown | Test | 
| Impartner.Account.crmHash | Unknown | Test | 
| Impartner.Account.crmLastExportedHash | Unknown | Test | 
| Impartner.Account.currencyConversionRate | Unknown | Test | 
| Impartner.Account.dealsRegistered | Number | Test | 
| Impartner.Account.partnerLocator | Boolean | Test | 
| Impartner.Account.solutionLocator | Boolean | Test | 
| Impartner.Account.evalTierAfterExpired | Boolean | Test | 
| Impartner.Account.externalId1 | Unknown | Test | 
| Impartner.Account.externalId2 | Unknown | Test | 
| Impartner.Account.fax | Unknown | Test | 
| Impartner.Account.id | Number | Test | 
| Impartner.Account.isActive | Boolean | Test | 
| Impartner.Account.isFeatured | Boolean | Test | 
| Impartner.Account.isTest | Boolean | Test | 
| Impartner.Account.crmLastKnownDateUpdated | Unknown | Test | 
| Impartner.Account.crmLastImported | Unknown | Test | 
| Impartner.Account.crmLastExported | Unknown | Test | 
| Impartner.Account.updatedById | Number | Test | 
| Impartner.Account.crmLastExportedVersion | Unknown | Test | 
| Impartner.Account.mailingCity | String | Test | 
| Impartner.Account.mailingCountry | String | Test | 
| Impartner.Account.mailingCountryCode | String | Test | 
| Impartner.Account.mailingLatitude | Number | Test | 
| Impartner.Account.mailingLongitude | Number | Test | 
| Impartner.Account.mailingPostalCode | String | Test | 
| Impartner.Account.mailingState | String | Test | 
| Impartner.Account.mailingStreet | String | Test | 
| Impartner.Account.mailingSuite | String | Test | 
| Impartner.Account.memberCount | Number | Test | 
| Impartner.Account.name | String | Test | 
| Impartner.Account.nonDealSales | Number | Test | 
| Impartner.Account.parentAccountId | Unknown | Test | 
| Impartner.Account.partnerLevelId | Number | Test | 
| Impartner.Account.phone | String | Test | 
| Impartner.Account.primaryUserId | Number | Test | 
| Impartner.Account.recordLink | String | Test | 
| Impartner.Account.recordVersion | Number | Test | 
| Impartner.Account.referralUrl | Unknown | Test | 
| Impartner.Account.referralUrlSegment | Unknown | Test | 
| Impartner.Account.regionId | Unknown | Test | 
| Impartner.Account.revenue | Number | Test | 
| Impartner.Account.revenueAttainment | Number | Test | 
| Impartner.Account.revenueGoal | Number | Test | 
| Impartner.Account.tcmaNotificationTriggerType | Unknown | Test | 
| Impartner.Account.tcmaNotificationTriggerValue | Unknown | Test | 
| Impartner.Account.tcmaShowcaseSegment | Unknown | Test | 
| Impartner.Account.tierId | Unknown | Test | 
| Impartner.Account.tierChangeType | String | Test | 
| Impartner.Account.tierOverrideById | Unknown | Test | 
| Impartner.Account.tierOverrideDate | Unknown | Test | 
| Impartner.Account.tierOverrideExpirationDate | Unknown | Test | 
| Impartner.Account.tierOverrideNote | Unknown | Test | 
| Impartner.Account.totalSales | Number | Test | 
| Impartner.Account.updated | Date | Test | 
| Impartner.Account.website | String | Test | 
| Impartner.Account.what_is_your_main_product_you_are_looking_to_integrate_with_Palo_Alto_Networks__cf | Unknown | Test | 
| Impartner.Account.if_other_please_name__cf | Unknown | Test | 
| Impartner.Account.if_yes_please_share_at_least_1_mutual_customer_that_will_use_and_test_the_integration__cf | Unknown | Test | 
| Impartner.Account.other_Product__cf | Unknown | Test | 
| Impartner.Account.what_is_the_name_of_your_product_that_you_d_like_to_integrate_with_our_product__cf | Unknown | Test | 
| Impartner.Account.if_other_please_explain__cf | Unknown | Test | 
| Impartner.Account.tpA_Product_s__cf | String | Test | 
| Impartner.Account.status__cf | Unknown | Test | 
| Impartner.Account.ignite_Sponsorship_Years__cf | Unknown | Test | 
| Impartner.Account.account_SLUG__cf | String | Test | 
| Impartner.Account.nfR_CN_Series_Eval_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_CN_Series_SFDC_link__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_XDR_Eval_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_XDR_SFDC_link__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_Xpanse_Eval_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_Xpanse_SFDC_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_Xsoar_Eval_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_Xsoar_SFDC_link__cf | Unknown | Test | 
| Impartner.Account.nfR_DLP_Eval_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Global_Protect_Eval_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Global_Protect_SFDC_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_IoT_Eval_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_IoT_SFDC_link__cf | Unknown | Test | 
| Impartner.Account.nfR_NGFW_Eval_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_NGFW_SFDC_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_Panorama_Eval_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Panorama_SFDC_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Access_Eval_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Access_SFDC_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Cloud_Eval_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Cloud_SFDC_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Cloud_Compute_Eval_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Cloud_Compute_SFDC_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_SASE_Security_Eval_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_SASE_Security_SFDC_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_SD_WAN_Eval_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_SD_WAN_SFDC_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_VM_Series_Eval_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_VM_Series_SFDC_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_Wildfire_Eval_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Wildfire_SFDC_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_CN_Series_Eval_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_CN_Series_License_Type__cf | Unknown | Test | 
| Impartner.Account.nfR_CN_Series_Promo_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_XDR_Eval_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_XDR_License_Type__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_XDR_Promo_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_Xpanse_Eval_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_Xpanse_Promo_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_Xpanse_License_Type__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_Xsoar_Eval_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_Xsoar_License_Type__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_Xsoar_Promo_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_DLP_SFDC_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_DLP_Eval_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_DLP_License_Type__cf | Unknown | Test | 
| Impartner.Account.nfR_DLP_Promo_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Global_Protect_Eval_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_Global_Protect_License_Type__cf | Unknown | Test | 
| Impartner.Account.nfR_Global_Protect_Promo_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_IoT_Eval_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_IoT_License_Type__cf | Unknown | Test | 
| Impartner.Account.nfR_IoT_Promo_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_NGFW_Eval_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_NGFW_License_Type__cf | Unknown | Test | 
| Impartner.Account.nfR_Panorama_Eval_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_Panorama_License_Type__cf | Unknown | Test | 
| Impartner.Account.nfR_Panorama_Promo_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Access_Eval_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Access_License_Type__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Access_Promo_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Cloud_Eval_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Cloud_License_Type__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Cloud_Promo_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Cloud_Compute_Eval_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Cloud_Compute_License_Type__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Cloud_Compute_Promo_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_SASE_Security_Eval_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_SASE_Security_License_Type__cf | Unknown | Test | 
| Impartner.Account.nfR_SASE_Security_Promo_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_VM_Series_Eval_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_VM_Series_License_Type__cf | Unknown | Test | 
| Impartner.Account.nfR_VM_Series_Promo_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_SD_WAN_Eval_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_SD_WAN_License_Type__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_SD_WAN_Promo_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_Wildfire_Eval_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_Wildfie_License_Type__cf | Unknown | Test | 
| Impartner.Account.nfR_Wildfire_Promo_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_5G_OT_Eval_Id__cf | Unknown | Test | 
| Impartner.Account.nfR_5G_OT_SFDC_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_5G_OT_Eval_Link__cf | Unknown | Test | 
| Impartner.Account.nfR_5G_OT_License_Type__cf | Unknown | Test | 
| Impartner.Account.parent_Company_Legal_Name__cf | Unknown | Test | 
| Impartner.Account.location_of_Parent_Company_Country__cf | Unknown | Test | 
| Impartner.Account.does_the_Parent_Company_have_an_alternate_legal_name_in_another_language__cf | Unknown | Test | 
| Impartner.Account.company_Legal_Name__cf | Unknown | Test | 
| Impartner.Account.does_the_Company_have_other_Trading_Business_Name_or_name_in_another_language__cf | Unknown | Test | 
| Impartner.Account.legal_Address_street_city_country_postal_code__cf | Unknown | Test | 
| Impartner.Account.business_Telephone_Number__cf | Unknown | Test | 
| Impartner.Account.other_Business_address_or_Place_of_Business_street_city_state_country_postal_code__cf | Unknown | Test | 
| Impartner.Account.date_of_Incorporation_or_Registration_with_local_authorities__cf | Unknown | Test | 
| Impartner.Account.tax_ID_Number__cf | Unknown | Test | 
| Impartner.Account.what_country_is_the_integration_work_being_performed_in__cf | Unknown | Test | 
| Impartner.Account.if_you_have_multiple_legal_entity_names_which_entity_is_performing_the_integration_work__cf | Unknown | Test | 
| Impartner.Account.please_provide_the_address_of_the_entity_performing_the_integration_work__cf | Unknown | Test | 
| Impartner.Account.state_or_Province_of_Registration__cf | Unknown | Test | 
| Impartner.Account.marketplace_Long_Description__cf | String | Test | 
| Impartner.Account.marketplace_Short_Description__cf | String | Test | 
| Impartner.Account.what_is_the_use_case_you_are_trying_to_solve_in_the_integration__cf | Unknown | Test | 
| Impartner.Account.how_will_your_integration_with_Palo_Alto_Networks_offer_unique_benefits_to_the_customer__cf | Unknown | Test | 
| Impartner.Account.who_are_the_target_customers__cf | Unknown | Test | 
| Impartner.Account.what_is_the_integration_value_proposition_to_the_customers__cf | Unknown | Test | 
| Impartner.Account.what_is_the_integration_value_proposition_to_Palo_Alto_Networks__cf | Unknown | Test | 
| Impartner.Account.if_Yes_please_provide_details__cf | Unknown | Test | 
| Impartner.Account.if_not_who_is_the_authorized_person_to_sign_this_agreement_on_behalf_of_the_company_please_share_ema__cf | Unknown | Test | 
| Impartner.Account.if_so_please_provide_publicly_disclosable_details_Optional_Please_note_the_purpose_of_this_question___cf | Unknown | Test | 
| Impartner.Account.tell_us_about_your_company__cf | Unknown | Test | 
| Impartner.Account.what_are_the_other_use_case_you_are_trying_to_solve_in_the_integration__cf | Unknown | Test | 
| Impartner.Account.notes_from_BD__cf | Unknown | Test | 
| Impartner.Account.application_Notes__cf | Unknown | Test | 
| Impartner.Account.what_are_the_names_of_the_specific_companies_you_are_targeting_with_this_integration__cf | Unknown | Test | 
| Impartner.Account.due_to_the_current_volume_of_applications_the_requirement_is_at_least_2_joint_customers_that_are_wil__cf | Unknown | Test | 
| Impartner.Account.if_you_do_have_a_way_please_describe__cf | Unknown | Test | 
| Impartner.Account.engineer_Tech_BD_Notes__cf | Unknown | Test | 
| Impartner.Account.please_choose_the_integration_type_for_the_main_integration__cf | Unknown | Test | 
| Impartner.Account.what_is_the_1st_priority_Palo_Alto_product_you_want_to_integrate_with__cf | Unknown | Test | 
| Impartner.Account.which_other_Palo_products_you_are_interested_in_integrating_with__cf | Unknown | Test | 
| Impartner.Account.what_is_the_2nd_priority_Palo_Alto_product_you_want_to_integrate_with__cf | Unknown | Test | 
| Impartner.Account.is_there_a_Joint_Customer_or_Prospect_asking_for_integrating_your_product_with_Palo_Alto_products__cf | Unknown | Test | 
| Impartner.Account.how_many_customers_do_you_expect_will_use_the_integration_in_the_next_2_years__cf | Unknown | Test | 
| Impartner.Account.is_the_planned_integration_with_Palo_Alto_Networks_budgeted_and_resourced__cf | Unknown | Test | 
| Impartner.Account.has_an_integration_with_this_product_already_been_done_and_or_has_PoC_of_Integration_been_completed__cf | Unknown | Test | 
| Impartner.Account.has_an_integration_between_your_product_and_other_Security_Vendors_in_the_same_space_been_done_befor__cf | Unknown | Test | 
| Impartner.Account.are_you_authorized_to_sign_the_technology_partner_agreement__cf | Unknown | Test | 
| Impartner.Account.featured__cf | Unknown | Test | 
| Impartner.Account.number_of__cf | Unknown | Test | 
| Impartner.Account.integration_Status__cf | String | Test | 
| Impartner.Account.are_there_other_use_cases_for_this_integration__cf | Unknown | Test | 
| Impartner.Account.validated__cf | Unknown | Test | 
| Impartner.Account.do_you_have_a_way_to_track_who_will_use_the_integration__cf | Unknown | Test | 
| Impartner.Account.if_the_integration_is_approved_can_you_commit_to_completing_it_within_90_day_including_the_Integrati__cf | Unknown | Test | 
| Impartner.Account.nfR_CN_Series_Notify__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_XDR_notify__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_Xpanse_Notify__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_Xsoar_Notify__cf | Unknown | Test | 
| Impartner.Account.nfR_DLP_Notify__cf | Unknown | Test | 
| Impartner.Account.nfR_Global_Protect_Notify__cf | Unknown | Test | 
| Impartner.Account.nfR_Iot_Notify__cf | Unknown | Test | 
| Impartner.Account.nfR_NGFW_Notify__cf | Unknown | Test | 
| Impartner.Account.nfR_Panorama_Notify__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Access_Notify__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Cloud_Notify__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Cloud_Compute_Notify__cf | Unknown | Test | 
| Impartner.Account.nfR_SASE_Security_Notify__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_SD_WAN_Notify__cf | Unknown | Test | 
| Impartner.Account.nfR_VM_Series_Notify__cf | Unknown | Test | 
| Impartner.Account.nfR_Wildfire_Notify__cf | Unknown | Test | 
| Impartner.Account.nfR_5G_OT_Nofity__cf | Unknown | Test | 
| Impartner.Account.tech_BD_Assigned_for_XSOAR__cf | Unknown | Test | 
| Impartner.Account.does_the_Company_have_other_Business_Address_or_Place_of_Business__cf | Unknown | Test | 
| Impartner.Account.does_your_company_have_subsidiaries__cf | Unknown | Test | 
| Impartner.Account.integration_was_expired__cf | Unknown | Test | 
| Impartner.Account.target_customers__cf | Unknown | Test | 
| Impartner.Account.which_Region_the_company_is_serving__cf | Unknown | Test | 
| Impartner.Account.company_Main_Market_Segment__cf | Unknown | Test | 
| Impartner.Account.what_do_you_need_from_PANW_to_make_this_work_as_part_of_the_partnerships__cf | Unknown | Test | 
| Impartner.Account.panW_Integration_Product__cf | Unknown | Test | 
| Impartner.Account.account_Integration_Status__cf | String | Test | 
| Impartner.Account.panW_Integration_Product_Approved__cf | String | Test | 
| Impartner.Account.tiers__cf | Unknown | Test | 
| Impartner.Account.integration_Form_Approved__cf | Unknown | Test | 
| Impartner.Account.completed_Integration_Form_Approved__cf | Unknown | Test | 
| Impartner.Account.initial_Integration_Form_Approval_Email_Notification_Sent__cf | Unknown | Test | 
| Impartner.Account.completed_Integration_Form_Approved_Notification_Sent__cf | Unknown | Test | 
| Impartner.Account.integration_Demo_Approved__cf | Unknown | Test | 
| Impartner.Account.integration_Guide_Approved__cf | Unknown | Test | 
| Impartner.Account.panW_Integration_Product_Expired__cf | Unknown | Test | 
| Impartner.Account.panW_Integration_Product_Expired_notification_sent__cf | Unknown | Test | 
| Impartner.Account.if_there_is_a_timeline_to_complete_the_integration_please_enter_the_date__cf | Unknown | Test | 
| Impartner.Account.tpA_Signed__cf | Date | Test | 
| Impartner.Account.tpA_Expiration_DAte__cf | Date | Test | 
| Impartner.Account.last_Conversation_Date_with_BD__cf | Unknown | Test | 
| Impartner.Account.ndA_Signed__cf | Unknown | Test | 
| Impartner.Account.nfR_CN_Series_Iss_Date__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_XDR_Iss_date__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_Xpanse_Iss_Date__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_Xsoar_Iss_Date__cf | Unknown | Test | 
| Impartner.Account.nfR_DLP_Iss_Date__cf | Unknown | Test | 
| Impartner.Account.nfR_Global_Protect_Iss_Date__cf | Unknown | Test | 
| Impartner.Account.nfR_IoT_Iss_Date__cf | Unknown | Test | 
| Impartner.Account.nfR_NGFW_Iss_Date__cf | Unknown | Test | 
| Impartner.Account.nfR_Panorama_Iss_Date__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Access_Iss_Date__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Cloud_Iss_Date__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Cloud_Compute_Iss_Date__cf | Unknown | Test | 
| Impartner.Account.nfR_SASE_Security_Iss_Date__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_SD_WAN_Iss_Date__cf | Unknown | Test | 
| Impartner.Account.nfR_VM_Series_Iss_Date__cf | Unknown | Test | 
| Impartner.Account.nfR_Wildfire_Iss_Date__cf | Unknown | Test | 
| Impartner.Account.nfR_5G_OT_Iss_Date__cf | Unknown | Test | 
| Impartner.Account.number_of_Customers__cf | Unknown | Test | 
| Impartner.Account.nfR_CN_Series_Email__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_XDR_email__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_Xpanse_Email__cf | Unknown | Test | 
| Impartner.Account.nfR_Cortex_Xsoar_Email__cf | Unknown | Test | 
| Impartner.Account.nfR_DLP_Email__cf | Unknown | Test | 
| Impartner.Account.nfR_Global_Protect_Email__cf | Unknown | Test | 
| Impartner.Account.nfR_IoT_Email__cf | Unknown | Test | 
| Impartner.Account.nfR_NGFW_Email__cf | Unknown | Test | 
| Impartner.Account.nfR_Panorama_Email__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Access_Email__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_Cloud_Email__cf | Unknown | Test | 
| Impartner.Account.nfR_Primsa_Cloud_Compute_Email__cf | Unknown | Test | 
| Impartner.Account.nfR_SASE_Security_Email__cf | Unknown | Test | 
| Impartner.Account.nfR_Prisma_SD_WAN_Email__cf | Unknown | Test | 
| Impartner.Account.nfR_VM_Series_Email__cf | Unknown | Test | 
| Impartner.Account.nfR_Wildfire_Email__cf | Unknown | Test | 
| Impartner.Account.nfR_5G_OT_Email__cf | Unknown | Test | 
| Impartner.Account.nfR_NGFW_Promo_Id__cf | Unknown | Test | 

#### Command example
```!impartner-get-account-id id=2247998```
#### Context Example
```json
{
    "Impartner": {
        "Account": {
            "accountManagerId": null,
            "account_Integration_Status__cf": [
                "Integrations in Process"
            ],
            "account_SLUG__cf": "test",
            "application_Notes__cf": "Test note",
            "are_there_other_use_cases_for_this_integration__cf": "Yes",
            "are_you_authorized_to_sign_the_technology_partner_agreement__cf": "Yes",
            "autoAssignRegion": true,
            "autoAssignTier": false,
            "business_Telephone_Number__cf": null,
            "comments": null,
            "company_Legal_Name__cf": null,
            "company_Main_Market_Segment__cf": [
                "Cloud Security",
                "Detection & Response",
                "Email Security",
                "SaaS",
                "Security Tools Assessment",
                "Threat Intelligence",
                "Vulnerability Management"
            ],
            "completed_Integration_Form_Approved_Notification_Sent__cf": null,
            "completed_Integration_Form_Approved__cf": null,
            "convertedApplicantId": 1595577,
            "created": "2023-12-21T11:06:35-07:00",
            "createdById": 3234576,
            "crmAccountType": null,
            "crmHash": null,
            "crmId": null,
            "crmLastExported": null,
            "crmLastExportedHash": null,
            "crmLastExportedVersion": null,
            "crmLastImported": null,
            "crmLastKnownDateUpdated": null,
            "currencyConversionRate": null,
            "date_of_Incorporation_or_Registration_with_local_authorities__cf": null,
            "dealsRegistered": 0,
            "do_you_have_a_way_to_track_who_will_use_the_integration__cf": "Yes",
            "does_the_Company_have_other_Business_Address_or_Place_of_Business__cf": null,
            "does_the_Company_have_other_Trading_Business_Name_or_name_in_another_language__cf": null,
            "does_the_Parent_Company_have_an_alternate_legal_name_in_another_language__cf": null,
            "does_your_company_have_subsidiaries__cf": null,
            "due_to_the_current_volume_of_applications_the_requirement_is_at_least_2_joint_customers_that_are_wil__cf": null,
            "engineer_Tech_BD_Notes__cf": null,
            "evalTierAfterExpired": false,
            "externalId1": null,
            "externalId2": null,
            "fax": null,
            "faxAlternate": null,
            "featured__cf": null,
            "has_an_integration_between_your_product_and_other_Security_Vendors_in_the_same_space_been_done_befor__cf": "Yes",
            "has_an_integration_with_this_product_already_been_done_and_or_has_PoC_of_Integration_been_completed__cf": "No",
            "how_many_customers_do_you_expect_will_use_the_integration_in_the_next_2_years__cf": null,
            "how_will_your_integration_with_Palo_Alto_Networks_offer_unique_benefits_to_the_customer__cf": null,
            "id": 2247998,
            "if_Yes_please_provide_details__cf": null,
            "if_not_who_is_the_authorized_person_to_sign_this_agreement_on_behalf_of_the_company_please_share_ema__cf": null,
            "if_other_please_explain__cf": null,
            "if_other_please_name__cf": null,
            "if_so_please_provide_publicly_disclosable_details_Optional_Please_note_the_purpose_of_this_question___cf": "Test Purpose",
            "if_the_integration_is_approved_can_you_commit_to_completing_it_within_90_day_including_the_Integrati__cf": "Yes",
            "if_there_is_a_timeline_to_complete_the_integration_please_enter_the_date__cf": "2024-03-31T00:00:00",
            "if_yes_please_share_at_least_1_mutual_customer_that_will_use_and_test_the_integration__cf": "Carrier",
            "if_you_do_have_a_way_please_describe__cf": "Yes - via the API calls",
            "if_you_have_multiple_legal_entity_names_which_entity_is_performing_the_integration_work__cf": null,
            "ignite_Sponsorship_Years__cf": null,
            "initial_Integration_Form_Approval_Email_Notification_Sent__cf": null,
            "integration_Demo_Approved__cf": null,
            "integration_Form_Approved__cf": null,
            "integration_Guide_Approved__cf": null,
            "integration_Status__cf": "Integration in Process",
            "integration_was_expired__cf": null,
            "isActive": true,
            "isFeatured": false,
            "isTest": false,
            "is_the_planned_integration_with_Palo_Alto_Networks_budgeted_and_resourced__cf": "Yes",
            "is_there_a_Joint_Customer_or_Prospect_asking_for_integrating_your_product_with_Palo_Alto_products__cf": "Yes",
            "last_Conversation_Date_with_BD__cf": null,
            "legal_Address_street_city_country_postal_code__cf": null,
            "location_of_Parent_Company_Country__cf": null,
            "mailingCity": "City",
            "mailingCountry": "Country",
            "mailingCountryCode": "US",
            "mailingLatitude": 39.76116,
            "mailingLongitude": -75.62286,
            "mailingPostalCode": "1111",
            "mailingState": "State",
            "mailingStreet": "2 Street",
            "mailingSuite": null,
            "marketplace_Long_Description__cf": null,
            "marketplace_Short_Description__cf": null,
            "memberCount": 1,
            "name": "Test Name",
            "ndA_Signed__cf": null,
            "nfR_5G_OT_Email__cf": null,
            "nfR_5G_OT_Eval_Id__cf": null,
            "nfR_5G_OT_Eval_Link__cf": null,
            "nfR_5G_OT_Iss_Date__cf": null,
            "nfR_5G_OT_License_Type__cf": null,
            "nfR_5G_OT_Nofity__cf": null,
            "nfR_5G_OT_SFDC_Link__cf": null,
            "nfR_CN_Series_Email__cf": null,
            "nfR_CN_Series_Eval_Id__cf": null,
            "nfR_CN_Series_Eval_Link__cf": null,
            "nfR_CN_Series_Iss_Date__cf": null,
            "nfR_CN_Series_License_Type__cf": null,
            "nfR_CN_Series_Notify__cf": null,
            "nfR_CN_Series_Promo_Id__cf": null,
            "nfR_CN_Series_SFDC_link__cf": null,
            "nfR_Cortex_XDR_Eval_Id__cf": null,
            "nfR_Cortex_XDR_Eval_Link__cf": null,
            "nfR_Cortex_XDR_Iss_date__cf": null,
            "nfR_Cortex_XDR_License_Type__cf": null,
            "nfR_Cortex_XDR_Promo_Id__cf": null,
            "nfR_Cortex_XDR_SFDC_link__cf": null,
            "nfR_Cortex_XDR_email__cf": null,
            "nfR_Cortex_XDR_notify__cf": null,
            "nfR_Cortex_Xpanse_Email__cf": null,
            "nfR_Cortex_Xpanse_Eval_Id__cf": null,
            "nfR_Cortex_Xpanse_Eval_Link__cf": null,
            "nfR_Cortex_Xpanse_Iss_Date__cf": null,
            "nfR_Cortex_Xpanse_License_Type__cf": null,
            "nfR_Cortex_Xpanse_Notify__cf": null,
            "nfR_Cortex_Xpanse_Promo_Id__cf": null,
            "nfR_Cortex_Xpanse_SFDC_Link__cf": null,
            "nfR_Cortex_Xsoar_Email__cf": null,
            "nfR_Cortex_Xsoar_Eval_Id__cf": null,
            "nfR_Cortex_Xsoar_Eval_Link__cf": null,
            "nfR_Cortex_Xsoar_Iss_Date__cf": null,
            "nfR_Cortex_Xsoar_License_Type__cf": null,
            "nfR_Cortex_Xsoar_Notify__cf": null,
            "nfR_Cortex_Xsoar_Promo_Id__cf": null,
            "nfR_Cortex_Xsoar_SFDC_link__cf": null,
            "nfR_DLP_Email__cf": null,
            "nfR_DLP_Eval_Id__cf": null,
            "nfR_DLP_Eval_Link__cf": null,
            "nfR_DLP_Iss_Date__cf": null,
            "nfR_DLP_License_Type__cf": null,
            "nfR_DLP_Notify__cf": null,
            "nfR_DLP_Promo_Id__cf": null,
            "nfR_DLP_SFDC_Link__cf": null,
            "nfR_Global_Protect_Email__cf": null,
            "nfR_Global_Protect_Eval_Id__cf": null,
            "nfR_Global_Protect_Eval_Link__cf": null,
            "nfR_Global_Protect_Iss_Date__cf": null,
            "nfR_Global_Protect_License_Type__cf": null,
            "nfR_Global_Protect_Notify__cf": null,
            "nfR_Global_Protect_Promo_Id__cf": null,
            "nfR_Global_Protect_SFDC_Link__cf": null,
            "nfR_IoT_Email__cf": null,
            "nfR_IoT_Eval_Id__cf": null,
            "nfR_IoT_Eval_Link__cf": null,
            "nfR_IoT_Iss_Date__cf": null,
            "nfR_IoT_License_Type__cf": null,
            "nfR_IoT_Promo_Id__cf": null,
            "nfR_IoT_SFDC_link__cf": null,
            "nfR_Iot_Notify__cf": null,
            "nfR_NGFW_Email__cf": null,
            "nfR_NGFW_Eval_Id__cf": null,
            "nfR_NGFW_Eval_Link__cf": null,
            "nfR_NGFW_Iss_Date__cf": null,
            "nfR_NGFW_License_Type__cf": null,
            "nfR_NGFW_Notify__cf": null,
            "nfR_NGFW_Promo_Id__cf": null,
            "nfR_NGFW_SFDC_Link__cf": null,
            "nfR_Panorama_Email__cf": null,
            "nfR_Panorama_Eval_Id__cf": null,
            "nfR_Panorama_Eval_Link__cf": null,
            "nfR_Panorama_Iss_Date__cf": null,
            "nfR_Panorama_License_Type__cf": null,
            "nfR_Panorama_Notify__cf": null,
            "nfR_Panorama_Promo_Id__cf": null,
            "nfR_Panorama_SFDC_Link__cf": null,
            "nfR_Primsa_Cloud_Compute_Email__cf": null,
            "nfR_Prisma_Access_Email__cf": null,
            "nfR_Prisma_Access_Eval_Id__cf": null,
            "nfR_Prisma_Access_Eval_Link__cf": null,
            "nfR_Prisma_Access_Iss_Date__cf": null,
            "nfR_Prisma_Access_License_Type__cf": null,
            "nfR_Prisma_Access_Notify__cf": null,
            "nfR_Prisma_Access_Promo_Id__cf": null,
            "nfR_Prisma_Access_SFDC_Link__cf": null,
            "nfR_Prisma_Cloud_Compute_Eval_Id__cf": null,
            "nfR_Prisma_Cloud_Compute_Eval_Link__cf": null,
            "nfR_Prisma_Cloud_Compute_Iss_Date__cf": null,
            "nfR_Prisma_Cloud_Compute_License_Type__cf": null,
            "nfR_Prisma_Cloud_Compute_Notify__cf": null,
            "nfR_Prisma_Cloud_Compute_Promo_Id__cf": null,
            "nfR_Prisma_Cloud_Compute_SFDC_Link__cf": null,
            "nfR_Prisma_Cloud_Email__cf": null,
            "nfR_Prisma_Cloud_Eval_Id__cf": null,
            "nfR_Prisma_Cloud_Eval_Link__cf": null,
            "nfR_Prisma_Cloud_Iss_Date__cf": null,
            "nfR_Prisma_Cloud_License_Type__cf": null,
            "nfR_Prisma_Cloud_Notify__cf": null,
            "nfR_Prisma_Cloud_Promo_Id__cf": null,
            "nfR_Prisma_Cloud_SFDC_Link__cf": null,
            "nfR_Prisma_SD_WAN_Email__cf": null,
            "nfR_Prisma_SD_WAN_Eval_Id__cf": null,
            "nfR_Prisma_SD_WAN_Eval_Link__cf": null,
            "nfR_Prisma_SD_WAN_Iss_Date__cf": null,
            "nfR_Prisma_SD_WAN_License_Type__cf": null,
            "nfR_Prisma_SD_WAN_Notify__cf": null,
            "nfR_Prisma_SD_WAN_Promo_Id__cf": null,
            "nfR_Prisma_SD_WAN_SFDC_Link__cf": null,
            "nfR_SASE_Security_Email__cf": null,
            "nfR_SASE_Security_Eval_Id__cf": null,
            "nfR_SASE_Security_Eval_Link__cf": null,
            "nfR_SASE_Security_Iss_Date__cf": null,
            "nfR_SASE_Security_License_Type__cf": null,
            "nfR_SASE_Security_Notify__cf": null,
            "nfR_SASE_Security_Promo_Id__cf": null,
            "nfR_SASE_Security_SFDC_Link__cf": null,
            "nfR_VM_Series_Email__cf": null,
            "nfR_VM_Series_Eval_Id__cf": null,
            "nfR_VM_Series_Eval_Link__cf": null,
            "nfR_VM_Series_Iss_Date__cf": null,
            "nfR_VM_Series_License_Type__cf": null,
            "nfR_VM_Series_Notify__cf": null,
            "nfR_VM_Series_Promo_Id__cf": null,
            "nfR_VM_Series_SFDC_Link__cf": null,
            "nfR_Wildfie_License_Type__cf": null,
            "nfR_Wildfire_Email__cf": null,
            "nfR_Wildfire_Eval_Id__cf": null,
            "nfR_Wildfire_Eval_Link__cf": null,
            "nfR_Wildfire_Iss_Date__cf": null,
            "nfR_Wildfire_Notify__cf": null,
            "nfR_Wildfire_Promo_Id__cf": null,
            "nfR_Wildfire_SFDC_Link__cf": null,
            "nonDealSales": 0,
            "notes_from_BD__cf": null,
            "number_of_Customers__cf": 10000,
            "number_of__cf": "501+",
            "other_Business_address_or_Place_of_Business_street_city_state_country_postal_code__cf": null,
            "other_Product__cf": null,
            "panW_Integration_Product_Approved__cf": null,
            "panW_Integration_Product_Expired__cf": null,
            "panW_Integration_Product_Expired_notification_sent__cf": null,
            "panW_Integration_Product__cf": [
                "Cortex Xpanse",
                "Cortex XSOAR"
            ],
            "parentAccountId": null,
            "parent_Company_Legal_Name__cf": null,
            "partnerLevelId": 1229,
            "partnerLocator": true,
            "phone": null,
            "phoneAlternate": null,
            "please_choose_the_integration_type_for_the_main_integration__cf": "API",
            "please_provide_the_address_of_the_entity_performing_the_integration_work__cf": null,
            "primaryUserId": 5283648,
            "recordLink": "https://test.impartner.live/load/ACT/111",
            "recordVersion": 8,
            "referralUrl": null,
            "referralUrlSegment": null,
            "regionId": null,
            "revenue": 0,
            "revenueAttainment": 0,
            "revenueGoal": 0,
            "site": null,
            "solutionLocator": false,
            "state_or_Province_of_Registration__cf": null,
            "status__cf": null,
            "target_customers__cf": [
                "Large Enterprise",
                "MSSPs",
                "SME"
            ],
            "tax_ID_Number__cf": null,
            "tcmaNotificationTriggerType": null,
            "tcmaNotificationTriggerValue": null,
            "tcmaShowcaseSegment": null,
            "tech_BD_Assigned_for_XSOAR__cf": "Edi",
            "tell_us_about_your_company__cf": "Test description",
            "tierChangeType": "None",
            "tierId": null,
            "tierOverrideById": null,
            "tierOverrideDate": null,
            "tierOverrideExpirationDate": null,
            "tierOverrideNote": null,
            "tiers__cf": null,
            "totalSales": 0,
            "tpA_Expiration_DAte__cf": null,
            "tpA_Product_s__cf": "Cortex XSOAR, Cortex XSIAM",
            "tpA_Signed__cf": "2023-12-20T00:00:00",
            "updated": "2024-07-01T16:55:44-06:00",
            "updatedById": 3234576,
            "validated__cf": null,
            "website": "www.test.com",
            "what_are_the_names_of_the_specific_companies_you_are_targeting_with_this_integration__cf": null,
            "what_are_the_other_use_case_you_are_trying_to_solve_in_the_integration__cf": "Test Use case",
            "what_country_is_the_integration_work_being_performed_in__cf": null,
            "what_do_you_need_from_PANW_to_make_this_work_as_part_of_the_partnerships__cf": [
                "Product access",
                "Testing and certification"
            ],
            "what_is_the_1st_priority_Palo_Alto_product_you_want_to_integrate_with__cf": "Cortex XSOAR",
            "what_is_the_2nd_priority_Palo_Alto_product_you_want_to_integrate_with__cf": null,
            "what_is_the_integration_value_proposition_to_Palo_Alto_Networks__cf": "Value proposition",
            "what_is_the_integration_value_proposition_to_the_customers__cf": null,
            "what_is_the_name_of_your_product_that_you_d_like_to_integrate_with_our_product__cf": null,
            "what_is_the_use_case_you_are_trying_to_solve_in_the_integration__cf": "Test use case",
            "what_is_your_main_product_you_are_looking_to_integrate_with_Palo_Alto_Networks__cf": "DomainSec and the required APIs (i.e. Domain Management, Brand Protection, Fraud Protection)",
            "which_Region_the_company_is_serving__cf": [
                "Asia-Pacific",
                "Central and South America",
                "EMEA",
                "NAM"
            ],
            "which_other_Palo_products_you_are_interested_in_integrating_with__cf": null,
            "who_are_the_target_customers__cf": "test"
        }
    }
}
```

#### Human Readable Output

>### Account Details
>|Name|ID|Link|PST Engineer|
>|---|---|---|---|
>| CSC Digital Brand Services | 2247998 | https:<span>//</span>prod.impartner.live/load/ACT/2247998 | Edi |

