ReliaQuest GreyMatter DRP Incidents minimize digital risk by identifying unwanted exposure and protecting against external threats. The award-winning ReliaQuest GreyMatter DRP solution provides ongoing monitoring of a customer's unique assets and exposure across the open, deep, and dark web. This enables clients to detect data loss, brand impersonation, infrastructure risks, cyber threats, and much more.

This integration fetches event items which can be either incident/alerts, for more information, see [here](https://portal-digitalshadows.com/learn/searchlight-api/key-words/triage).

## ReliaQuest GreyMatter DRP Incidents EventCollector Authentication
Requests to all operation endpoints require HTTP Basic authentication, using dedicated (high entropy) API credentials. These normally consist of a six character key, and a 32 character 'secret'. Note that you will not be able to use your normal email/password login details with the HTTP Basic authentication mechanism.

Contact your ReliaQuest GreyMatter DRP representative to obtain API credentials.

To authenticate the integration, you must have a username, password and account ID. To get the account ID, see [here](https://portal-digitalshadows.com/api/stored-objects/portal/searchlight-api-docs/SearchLightAPI_APIKey_AccountId2.pdf).

## Limitations
Increasing the Maximum number of events per fetch parameter to high numbers can cause rate-limits, however The integration will recover from those rate-limits automatically. For more information about rate-limits, see [here](https://portal-digitalshadows.com/learn/searchlight-api/overview/rate-limiting).

## Configuration Guide

## Request Digital Shadows API Credentials

To use the application you will need to request an API Key and secret from Digital Shadows Support. Email support@digitalshadows.com stating that you would like to utilize the Digital Shadows Cortex XSOAR Integration and your SearchLightTM account details to have a new API Key created and assigned to you. 

To find your SearchLightTM  account details; in the SearchLightTM  portal please navigate to: 
- ‘Learn’ > ‘API Documentation’  
- Use the left hand filter to select ‘Keywords’   
- Scroll down to ‘Account’ and the ID is displayed

## Configuration

To configure the Digital Shadows Integration with Cortex XSOAR, from your XSOAR instance, navigate to:
- Left navigation panel 
- ‘Settings’
- Type ‘ReliaQuest GreyMatter DRP’ in the search bar 
- Click on the gear icon 

Here you can give your settings a custom name and set up several settings: 

Input: 
- ‘Classifier’ - Recommended to select ‘ReliaQuest GreyMatter DRP Incidents Classifier’ 
- ‘Mapper’ - Recommended to select ‘Reliaquest GreyMatter DRP Incidents Mapper’ 
- ‘Server URL’ - API URL for calling, is https://api.searchlight.app
- accountId – Account ID obtained from Digital Shadows Portal 
- ‘API Key’ and ‘Secret’ - Obtained from Digital Shadows 
- Risk Types – ‘All’ is the default. These can also be selected individually.
- ‘Risk Level’ – ‘All’ is the default. These can also be selected individually. 
- ‘Ingest Rejected/Resolved/Closed Incidents’ – This is an optional check box.
- ‘Fetch Limit’ – The maximum number of Incidents to Fetch 
- ‘Incidents Fetch Interval’ - Scheduled time frame between polling Digital Shadows for data 
- ‘Start Date’ – Initial Date to start pulling data from. (Historical incidents)
- ‘Log Level’ – ‘Verbose’, ‘Debug’, or ‘Off’  

Click on the ‘Test results’ tab and click ‘Run test’ 
. If you receive a ‘Success’ message then the integration is configured and will begin populating the ‘Investigation’ > ‘Incidents’ dashboard 

Note: TAXII feeds can be set up in order to receive IOCs from Digital Shadows.  
