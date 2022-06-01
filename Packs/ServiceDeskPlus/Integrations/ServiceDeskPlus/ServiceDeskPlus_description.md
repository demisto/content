## Create an Integration Instance for Cloud
To create an instance of the Service Desk Plus integration, you need to get a Client ID, Client Secret, and Refresh Token.
Follow the next steps to create an instance:

1. Select the data center in which your data resides.
2. Register your app using [ZOHO App Registration](https://api-console.zoho.com). Make sure you copy the Client ID and Client Secret of the app to the Cortex XSOAR instance and click the **Done** button.
3. In the registered app, select the **Generate Code** tab and define the scopes for the app.
4. From the Cortex XSOAR CLI run the command `!service-desk-plus-generate-refresh-token` and paste the generated code into the code parameter.
5. Copy the generated refresh token to the Cortex XSOAR instance and click the **Test** button to validate the instance.

## Create an Integration Instance for On-Premise
To create an instance of the Service Desk Plus integration, you need to get a On-Premises Server URL and a Technician Key.

Follow the next steps to create an instance:

1. Enter the On-Premise Server URL info.
2. Enter the Technician Key.
3. Click the **Test** button to validate the instance.

**NOTES**
- For more details about the app authorization process refer to [App Authorization](https://www.manageengine.com/products/service-desk/sdpod-v3-api/SDPOD-V3-API.html)
- The code generated in the app is only valid for a limited time.
- In order to avoid repeating this process, the created Refresh Token should be saved for future use.
- For more details about generating a technician key please refer to the [help documentation](https://help.servicedeskplus.com/api/rest-api.html$key)

## Fetch-Incidents Query

Filters should be in the format "{field':<field_name>, 'condition':<condition>, 'values':'val_1,val_2', 'logical_operator':<op>}".
Supports comma-separated values, for example:
{"field":"technician.name", "condition":"is", "values":"tech1,tech2", "logical_operator":"AND"}, {"field":"due_by_time", "condition":"greater than", "values":"1592946000000", "logical_operator":"AND"}.
