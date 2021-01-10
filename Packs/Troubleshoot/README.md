This pack contains utilities for troubleshooting your environment. 

When encountering issues, make sure to check out our [Troubleshooting Guide](https://xsoar.pan.dev/docs/reference/articles/troubleshooting-guide).

# Troubleshooting Playbook

---
This playbook is meant for automatic troubleshooting when encountering a problem with configuring an 
instance or running a command.

The playbook will run the command/instance with several tests and will output a summary and a zip file with information
that you can later submit to the [CortexXSOAR support site](https://support.paloaltonetworks.com)

## How to use 

---
* Configure a [Demisto REST API integration](https://xsoar.pan.dev/docs/reference/articles/integrations-and-incident-health-check#1-demisto-rest-api-integration) instance.
* Create a new incident of type "Integration Troubleshooting"
* **Troubleshoot type**:
    * Use ***configuration*** if you fail to configure an integration (the test button returns an error). 
    Note you must save this integration even if the test button fails.
    * Use ***command*** if you fail to run a particular command.
* **Instance Name**: The name of the instance to troubleshoot.
* **Command Line**: Fill if you used the ***command*** as the **troubleshoot type**. (The command name with all its arguments.)
* Create the incident.
* The playbook will collect the following information:
    * Instance configuration (without sensitive information such as the password or api keys).
    * Logs of running the Test button with several configurations.
    * Logs of executing the command (if you picked ***command*** in **Troubleshoot type**).
* A summary will be posted to the War Room alongside a zip file that will contain all collected information.
* With this information you can submit a bug to the [CortexXSOAR support site](https://support.paloaltonetworks.com).
