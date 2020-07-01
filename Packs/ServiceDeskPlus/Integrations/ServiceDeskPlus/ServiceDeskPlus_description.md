## Instance Creation Flow

To create an instance for Service Desk Plus, a Client Id, Client secret and Refresh Token are required.

Follow the next steps to create an instance:

1. Choose the data center which your data resides in.
2. Register your app using [ZOHO App Registration](https://api-console.zoho.com), copy the Client Id and Client Secret of the app to the Demisto instance and hit the **Done** button.
3. In the registered app, select the Generate Code tab and define the desired scopes for the app.
4. In the Demisto CLI run the command !service-desk-plus-generate-refresh-token and paste the generated code into the code parameter.
5. Copy the generated refresh token to the Demisto instance and hit the **Test** button to validate the instance.

**NOTES**
- For more details about the app authorization process please refer to [App Authorization](https://www.manageengine.com/products/service-desk/sdpod-v3-api/SDPOD-V3-API.html)
- The code generated in the app is valid for a limited time only.
- In order to avoid repeating this process, the created Refresh Token should be saved for future use.

## Fetch-Incidents Query

Filter should be in the format "{field':<field_name>, 'condition':<condition>, 'values':'val_1,val_2', 'logical_operator':<op>}".
Multiple filters can be applied separated with a comma. For example:
{"field":"technician.name", "condition":"is", "values":"tech1,tech2", "logical_operator":"AND"}, {"field":"due_by_time", "condition":"greater than", "values":"1592946000000", "logical_operator":"AND"}.
