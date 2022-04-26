This content pack runs queries on Splunk servers.

When a query or alert triggers a notable event (incident) in Splunk, the event is stored in an index (table). An XSOAR analyst can fetch the event and its context data all from the XSOAR console. 

We strongly recommend you to use the SplunkPy pre-release version, specifically if you experience any issues regarding fetch logic, including (but not limited to) missing incidents.


## What does this pack do?
Using the SplunkPy integration, you can fetch Splunk notable events. The events contain details such as:
- The name of the alert that was triggered.
- The objects that make up the alert, such as the IP address, hashes, and user names.

Besides fetching notable events, the SplunkPy integration enables you to run drill down searches to retrieve additional data from other tables in Splunk such as:
- Data about the users (department, role, and geographical location)
- Data about the assets (such as hostname, IP address, geographical location, and department)

In addition, the integration enables mirroring between Splunk and Cortex XSOAR.  

**Note:**  
When mirroring or fetching incidents between Splunk to Cortex XSOAR, you need to [map Splunk users to Cortex XSOAR users](https://xsoar.pan.dev/docs/reference/integrations/splunk-py#use-cases).