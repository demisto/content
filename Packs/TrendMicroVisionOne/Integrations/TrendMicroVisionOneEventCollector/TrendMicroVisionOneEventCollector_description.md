Trend Micro Vision One is a purpose-built threat defense platform that provides added value and new benefits beyond XDR solutions, allowing you to see more and respond faster. Providing deep and broad extended detection and response (XDR) capabilities that collect and automatically correlate data across multiple security layers—email, endpoints, servers, cloud workloads, and networks—Trend Micro Vision One prevents the majority of attacks with automated protection.

This integration fetches the following logs/alerts from Trend Micro Vision One and requires the following permissions:


| **Log Type**                    | **Action Role Permission Required** | **Api Documentation**                                                                                                     |
|---------------------------------|-------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| Workbench Logs                  | Workbench                           | [Workbench Docs](https://automation.trendmicro.com/xdr/api-v3#tag/Workbench)                                              |
| Observed Attack Techniques Logs | Observed Attack Techniques          | [Observed Attack Techniques Docs](https://automation.trendmicro.com/xdr/api-v3#tag/Observed-Attack-Techniques)            |
| Search Detection Logs           | Search                              | [Search Detections Docs](https://automation.trendmicro.com/xdr/api-v3#tag/Search/paths/~1v3.0~1search~1endpointActivities/get) |
| Audit Logs                      | Audit Logs                          | [Audit Docs](https://automation.trendmicro.com/xdr/api-v3#tag/Audit-Logs)                                                 | 


***
You can then create a user account and generate an API key to be used for the Cortex XSIAM integration by following these steps in Trend Micro Vision One.

1. Navigate to **Administration** > **User Accounts**.
2. Click **Add Account**.
3. Fill in the **Add Account** details assigning the role you created in the previous step and choosing **APIs only** as the access level.
4. Complete the account creation process by following the steps in the email you receive.
5. This will generate an **Authentication token** that can then be used to configure the Cortex XSIAM integration.

***
**Built-in Roles:**
Trend Vision One has built-in roles with fixed permissions that Master Administrators can assign to accounts.

The following table provides a brief description of each role. 


| **Role**                          | **Description**                                                                                               |
|-----------------------------------|--------------------------------------------------------------------------------------------------------------- 
| Master Administrator              | Can access all apps and Trend Vision One features.                                                            |
| Operator (formerly Administrator) | Can configure system settings and connect products.                                                           |
| Auditor                           | Has "View" access to specific Trend Vision One apps and features.                                             |
| Senior Analyst                    | Can investigate XDR alerts, take response actions, approve managed XDR requests, and manage detection models. |
| Analyst                           | Can investigate XDR alerts and take response actions.                                                         |

***
Be sure to select the correct domain for **Your server URL** integration parameter. You can see the list [here](https://automation.trendmicro.com/xdr/Guides/First-Steps-Toward-Using-the-APIs) section [3] under "Obtain the domain name for your region."

***
### API Limitations
* You cannot retrieve audit logs that are older than 180 days. Therefore, if setting a first fetch that is more than 180 days, for audit logs it will be a maximum of 180 days.
* For API rate limits, refer [here](https://automation.trendmicro.com/xdr/Guides/API-Request-Limits)
* Observed Attack Techniques Logs and Search Detection Logs are fetched from the newest to the oldest as its the logs are returned in descending order from the api.
* For Observed Attack Techniques Logs and Search Detection Logs it is possible that the limit will be exceeded due to api limitations.