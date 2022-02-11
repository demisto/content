When a query or alert triggers a notable event (incident) in Splunk, the notable is stored in an index (table). An XSOAR analyst can fetch the notable event and its context data all from within the XSOAR console. 

We strongly recommend you to use *SplunkPy Pre Release* version, specifically if you experience any issues regarding fetch logic, including (but not limited to) missing incidents, using the pre release version is the first step you should take.
## What does this pack do?
Using the SplunkPy integration, you can fetch the Splunk notable events. The notable events contain details such as:
- The name of the alert that was triggered.
- The objects that make up the alert, such as the IP address, hashes, user names, etc.

Besides fetching notable events, the SplunkPy integration enables you to run drill down searches to retrieve additional data from other tables in Splunk such as:
- Data about the users (department, role, geographical location)
- Data about the assets (hostname, IP address, geographical location, department, etc.)

In addition, the integration enables mirroring from Splunk to XSOAR, from XSOAR to Splunk, and from/to XSOAR and Splunk.
