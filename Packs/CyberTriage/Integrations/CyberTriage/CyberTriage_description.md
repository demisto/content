This integration allows you to collect and analyze endpoint data using Cyber Triage.  It will send an agentless collection tool to the remote endpoint, retrieve volatile and file system data, and analyze it for evidence of an intrusion. 

### SETUP
To use this integration, you need the Team version of Cyber Triage (and not the Standalone desktop version). 

To configure the integration, you will need to enter: 
* **hostname** where the Cyber Triage server has been setup.
* **REST Port** of your Cyber Triage server. This currently cannot be changed in Cyber Triage. The port should be left as 9443. 
* **API Key** for the Cyber Triage REST API. You can find this in the "Deployment Mode"  tab of the server's option panel.
* **Username/Password** an administrative Windows account that can be used to run the collection tool on endpoints that need to be investigated. 

### STARTING A COLLECTION
After setting up an instance, you can start a collection by using the “ct-triage-endpoint" command. The hostname or IP of the target endpoint must be provided. 

After the collection has started, open a Cyber Triage client to review the data.  

### SUPPORT
If you have any problems or need an evaluation copy of Cyber Triage, then please email support@cybertriage.com.