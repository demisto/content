## Prerequisites
To set up Salesforce to work with Demisto:
Add a new connected App in salesforce by following the instruction [here](https://developer.salesforce.com/docs/atlas.en-us.api_rest.meta/api_rest/intro_defining_remote_access_applications.htm)
If you already have a connected App, go to “Setup” -> “App Manager” -> choose the correct App from the list and press “View”.
The Consumer Key / Secret is under “API (Enable OAuth Settings)”
For detailed instructions see the Credentials walkthrough section at [demisto support](https://support.demisto.com/hc/en-us/articles/360001848133-Integration-Salesforce).

## Enable/Disable CRUD Commands
You can select which CRUD commands are enabled in the integration instance configuration settings. By default, all commands are enabled.

## Mandatory fields in Creating User Command
When creating a user in salesforce there are some mandatory fields, some are set as the default in the integration params:
Default Local Sid Key, Default Email Encoding Key and Default Language Locale Key.
ProfileId and Timezone Sid Key are part of the mapping fields and you need to map the proper values to them,
in order to do so change the *DemoGenerateProfileId* and the *DemoGenerateTimeZone* automations and use them as transformers to fit your settings.

## Add Custom Indicator Fields
Follow these steps to add custom fields to the User Profile indicator.

1. In XSOAR, create the custom indicator and incident field, for example, **Middle Name**.
2. Duplicate the **User Profile - Salesforce (Incoming)** mapper and/or the **User Profile - Salesforce (Outging)** mapper.
3. Add and map the custom field to the necessary mapper(s).
4. Go to the Salesforce IAM integration instance and in the mapper textbox, replace the name of the default mapper with the custom mapper you created.

## Automatically create user if not found in update command
The *create-if-not-exists* parameter specifies if a new user should be created when the User Profile passed was not found in the 3rd-party integration.
