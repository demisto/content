# Pack Documentation
This pack helps manage crises such as pandemics or other events that would change the conditions under which employees would normally work.



##### Triggers
The incident can be triggered manually or scheduled as a job. The incident type should be `Employee Health Check`. When the incident is created you are required to enter the `Manager Email` - The email of the manager whose direct reports should be contacted for their health status and offered assistance. The main playbook, `Employee Status Survey` will run.

##### Configuration
- Configure the `Microsoft Graph User` integration.
- Make sure the employees you want to contact when triggering an incident are configured in Azure AD as the direct reports of the manager you will enter on incident creation.
- Configure Slack and/or one of the following mail sender integrations:
  - EWS Mail Sender
  - Gmail
  - Mail Sender (New)
- In the `Employee Status Survey` playbook, edit task "Send employee status questionnaire" (task #13) and choose whether you want employees to be contacted by email, by Slack, or both.
- Optional - go to the "Timing" tab of the aforementioned task and edit the settings.

*Note: should you choose to edit the reply options in that task, you will have to to edit the `Process Survey Response` playbook to make sure the logic works correctly, as the reply options are later referenced by their numbers. Additionally, fields will need to be edited, as the reply options for how the employee feels are then set in a single-select field with predefined values.*

##### Main Playbook Stages and Capabilities



##### Best Practices & Suggestions


##### Visualization
