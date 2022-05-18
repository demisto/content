## Humio and XSOAR Integration 
Humio is a log management platform that allows customers to ingest everything to answer anything.
Humio provides comprehensive visibility for Security Operations and can ingest unlimited data at any throughput to provide the full data set needed to detect and respond to any incident. 
Live searches and real-time dashboards cut detection times and blazing fast search empowers threat hunting teams to unleash their curiosity.

This pack provides a means to enable API integration between Humio and XSOAR so that XSOAR can use Humio commands in playbooks.
The pack needs configuring with only a few key pieces of data from your Humio instance to create the integration.
Once the Humio instance is created you can use Humio commands from the XSOAR CLI or playbooks.  This effectively enables XSOAR playbooks to automate and orchestrate response actions to Humio security detections and alerts. All relevant Humio data can be made available to XSOAR for use in the playbook and within a playbook XSOAR can execute further queries into Humio for additional relevant information.

Documentation for the pack includes typical examples of Humio commands to do things such as:

*Fetch alerts from Humio

*Submit searches to Humio and pull back the results

*Poll Humio

*Create new alerts and notifications in Humio

To find out more about humio visit [Humio.com](https://www.humio.com) and if you don't have access to Humio register for the completely free [Humio Community Edition](https://www.humio.com/getting-started/community-edition/)
