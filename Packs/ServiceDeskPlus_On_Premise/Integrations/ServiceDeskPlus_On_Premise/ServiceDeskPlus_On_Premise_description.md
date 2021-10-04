## Create an Integration Instance
To create an instance of the Service Desk Plus integration, you need to get a On-Premises Server URL and a Technician Key.

Follow the next steps to create an instance:

1. Enter the Server URL info.
2. Enter the Technician Key.
3. Click the **Test** button to validate the instance.

**NOTES**
- For more details about generating a technician key please refer to the [help documentation](https://help.servicedeskplus.com/api/rest-api.html$key)

## Fetch-Incidents Query

Filters should be in the format "{field':<field_name>, 'condition':<condition>, 'values':'val_1,val_2', 'logical_operator':<op>}".
Supports comma-separated values, for example:
{"field":"technician.name", "condition":"is", "values":"tech1,tech2", "logical_operator":"AND"}, {"field":"due_by_time", "condition":"greater than", "values":"1592946000000", "logical_operator":"AND"}.
