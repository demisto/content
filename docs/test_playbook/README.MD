# Overview
Demisto uses CircleCI to test each of our integrations. The tests run for **your** integration each time you commit to the content repo. Tests for **every** integration run nightly. Perhaps the easiest way to create a test playbook is via the Demisto Playbook Editor. This is the preferred way to create one.

### Every pull request _must_ have a test playbook. 

## Creating a Test Playbook

### Getting Started
To create a test playbook, navigate to the **Playbooks** tab in Demisto and click **New Playbook**. When running a test, it is often necessary for the first step to be **DeleteContext**, which is located under the **Utilities** section in the Task Library. 

"Delete Context" does just that, it deletes all of the context data. While not always vital, it ensures that a test playbook has a clean beginning to test from without conflicting data. This allows for a test to be "sterile" and can help us to eliminate unrelated issues from the test. 

Make sure to select "yes" for the field "all". Finally, click **okay** and connect the **Playbook Triggered** task to the **DeleteContext** task as shown below:

<img src="https://user-images.githubusercontent.com/42912128/50275566-51eaa780-0448-11e9-8089-b3631fff1274.png" width="250" align="middle">

### Testing a Command
It is important to test as many parts of the integration as possible, and we recommend that you have a task for each command. For this example we will look at the integration IPInfo, which accepts only one command called ```!ip```. A search for IPInfo in the Task Library will display the command "ip". Click **Add** to bring up the configuration options. 

When we run a test against an entity such as an IP address, or domain, we must select an entity that will give us the most *consistent* results. We will use Google's 8.8.8.8 as an example in the configuration below.

<img src="https://user-images.githubusercontent.com/42912128/50276007-8448d480-0449-11e9-9413-67a842a8ce72.png" width="400" align="middle">

Click **OK** to save your changes and finally connect the "ip" task to the "DeleteContext" task as shown below:

![connect delete and ip](https://user-images.githubusercontent.com/42912128/50736134-25fa5080-11c2-11e9-89c5-12844545b5ff.png)


### Verifying Results
When a command task is built we then need to verify that the results are what we expected to receive. For example, we know that the IP address 8.8.8.8 resolves to "Google". If we wanted to test that the IPInfo integration is working, we would use the 8.8.8.8 ip address and *verify* that the owner is "Google". 

To do this, we will open the **Task Library** and select **Create Task**. Click the radio button next to "Conditional" to open the options for conditions as seen below:

<img src="https://user-images.githubusercontent.com/42912128/50276352-6fb90c00-044a-11e9-8210-a4df27b9500c.png" width="400" align="middle">

Under the section "Condition for yes", click the **{}** option to bring up the source tool. You will see an option for the task we have just created called "#2 ip". Click the "Address" option. 

**Note:** If you need to filter or format the result, click "Filter and Operations" to do so.

<img src="https://user-images.githubusercontent.com/42912128/50276603-fff75100-044a-11e9-97ef-c848cc051985.png" width="400" align="middle">

We now must wrap the Context Path like this **${IP.Address}**. This tells Demisto that we are looking for the value present at that location.

Next, in the "Equals (String)" field enter our expected value of "8.8.8.8" and click ✅ followed by **Save**. Connect the tasks together. 

Lastly, we will close the investigation if the test is successful. To do this find "closeInvestigation" in the Task Library and click "add". For the "id" field, select "ID" path found under "Incident details" in the source tool. Click "OK" and connect the task to the others.

### Naming and Exporting the Playbook
We use a standard naming convention for our playbook tests which follows the format below:

```Integration_Name-Test```

Click "Save Version" and exit the Playbook editor.

Lastly, we need to download the YAML file for the Playbook we have just created. Click ![download button](https://user-images.githubusercontent.com/42912128/50277516-4d74bd80-044d-11e9-94b6-5195dd0db796.png) to export the playbook.

## Adding the Playbook to your Project
With the YAML file we have just created, edit the ```id```  to be the same as the field ```name```. Next we change the ```version``` field to "-1" to prevent changes. using the example above, the top of your YAML should look like this:

```yml
id: IPInfo-Test
version: -1
name: IPInfo-Test
```

## Contacting Demisto for instance credentials
In order to approve your contribution, you will have to provide Demisto with credentials to an instance of the integration in order to verify all the hard work you have done and consolidate it into Demisto.

## Exapmles
Example of a Test Playbook:
https://github.com/demisto/content/blob/master/TestPlaybooks/playbook-Carbon_Black_Response_Test.yml

Example of a Playbook Image - https://user-images.githubusercontent.com/7270217/41154872-459f93fe-6b24-11e8-848b-25ca71f59629.png






***

[Next step - Documentation](https://github.com/demisto/content/tree/master/docs/integration_documentation)
