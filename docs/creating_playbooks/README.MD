# Creating a Playbook

### Getting Started
To create a playbook, we begin by navigating to the **Playbooks** tab in Demisto and clicking **New Playbook**. 

### Adding a Command
Playbooks run commands that are found inm both an integration as well as scripts. For this example, we will look at the Integration IPInfo. IPInfo accepts only one command called ```!ip```. A search for ipinfo in the Task Library will display the command "ip". Click **Add** to bring up the configuration options. 

For this example, will use Google's 8.8.8.8 in the configuration below. You can tell the playbook to accept different values based on the context.

<img src="https://user-images.githubusercontent.com/42912128/50276007-8448d480-0449-11e9-9413-67a842a8ce72.png" width="400" align="middle">

Click **OK** to save your changes and finally connect "ip" task to the "Trigger" task.

### Verifying Results
Once we have built a command task, we can use conditional tasks to verify that the results are what we expected to receive. To do this, we will open the **Task Library** and select **Create Task**. Click the radio button next to "Conditional" to open the options for conditions as seen below:

<img src="https://user-images.githubusercontent.com/42912128/50276352-6fb90c00-044a-11e9-8210-a4df27b9500c.png" width="400" align="middle">

Under the section "Condition for yes", we will click the **{}** option to bring up the source tool. You will see an option for the task we have just created called "#2 ip". Click the "Address" option. 

**Please note:** If you need to filter or format the result, click "Filter and Operations" to do so.

<img src="https://user-images.githubusercontent.com/42912128/50276603-fff75100-044a-11e9-97ef-c848cc051985.png" width="400" align="middle">

We now must wrap the Context Path like this **${IP.Address}**. This tells Demisto that we are looking for the value present at that location.

Next, in the "Equals (String)" field enter our expected value of "8.8.8.8" and click ✅ followed by **Save**. Connect the tasks together. 

Click "Save" to save your playbook. You can attach playbooks to incidents to automate tasks that are related to that incident.