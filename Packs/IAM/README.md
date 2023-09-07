> **Note:** This pack is free for DEV and POC environments. For production environments, it is free for up to 100 provisioned users. For larger production usage, install additionally to this Pack one of the following ILM Subscription Packs: **ILM Subscription - Small Enterprise**, **ILM Subscription - Medium Enterprise**, **ILM Subscription - Large Enterprise** according to your organization size.
  
This Identity Lifecycle Management pack enables you to provision users from Workday into Active Directory, GitHub, ServiceNow and Okta by performing common HR operations. In addition, you can automatically synchronize users in multiple apps for users created in Okta.
  
The process of provisioning users, such as adding them to the right groups and roles, giving them proper permissions and access to the necessary tools and creating new users for them in every newly added app can be arduous and error prone. 
  
Using this content pack, you can automate this interface with your user-management and authentication tools to add users to your various applications, assign them necessary roles, and grant them access to all of the applications with which they will be working. 
In the user-provisioning flow, based on a report from Workday, the integration determines what operation needs to be performed - is this a new hire who needs to be added to the system, does a user's personal information need to be updated, or has the user left the company and needs to be disabled in sensitive systems?
Additionally, when implementing the app-sync workflow, users are assigned to, or unassigned from, applications in Okta, or when users are added or removed from Okta groups - the app-sync playbook will create, update, enable, or disable the user in the corresponding Cortex XSOAR instance.
  
With this pack, you can reduce the time your teams spend on HR and IT tasks and standardize the way you manage user provisioning.  
  
What does this pack do?  
  
- Pulls Workday reports and Okta application events with user updates
  
- Creates incidents for each user update in the system.  
  
- Determines which action needs to be performed based on the information in the Workday report. Each action has its designated playbook to add, update, or remove users from the system.

- Allows the user to determine the account creation and activation dates relative to the hire date.
  
- Identifies if a hire is an employee being rehired or a first-time hire.  
  
- Communicates with the relevant stakeholders to inform them of any errors that arose in the process.  
  
- Communicates with the relevant stakeholders to obtain necessary credentials.  
  
As part of this pack, you will also receive out-of-the-box incident and indicator layouts, mappers, fields, automations and a dashboard. All of these are easily customizable to suit the needs of your organization.  


For more information, please refer to the [Identity Lifecycle Management article](https://xsoar.pan.dev/docs/reference/articles/identity-lifecycle-management).  
  
![Dashboard](https://raw.githubusercontent.com/demisto/content/ca197a7b294f0ea80196113d8410f181407d2d15/Images/dashboard_page1.png)  
![Incident](https://raw.githubusercontent.com/demisto/content/096b217ba5b7fc274e077cac228a4df1265b8d2d/Images/incident_page1.PNG)  
![Indicator](https://raw.githubusercontent.com/demisto/content/096b217ba5b7fc274e077cac228a4df1265b8d2d/Images/indicator_page1.png)
