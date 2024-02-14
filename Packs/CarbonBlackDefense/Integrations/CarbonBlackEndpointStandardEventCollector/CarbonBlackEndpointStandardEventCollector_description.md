## Create an API Key
1. Create *access level* entry with the following **READ** permissions:
   * org.alerts.notes
   * org.xdr.metadata
   * org.alerts
   * org.alerts.tags
   * org.audits

2. Create the API key ([see documentation](https://developer.carbonblack.com/reference/carbon-black-cloud/authentication#authenticate-your-request)) with the following parameters:
    * Access Level Type = Custom
    * Custom Access Level = the name of the *access level* entry created in step 1.

## Fetching Audit Logs Important Note
* The API for audit logs sends consumable audit log entries starting from 3 days before the creation of the API Key. To fetch the latest audit logs available, it is recommended to create a new API key for this instance, as the instance will create entries for the earliest available logs first. 
* To prevent duplicate entries (in case of API key refresh) the integration instance will store the last fetched audit log entry time, and block fetches of older audit logs entries.
* It is not recommended to refresh the API key, as the integration will need time to recover to the latest audit logs available.