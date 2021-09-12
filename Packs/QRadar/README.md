QRadar aggregates and parses logs that come in from various data sources. The QRadar admin creates rules for detecting suspicious traffic, suspicious IDs, etc., and runs searches to obtain additional data about these offences.

## What does this pack do?
The integration in this pack automatically fetches the offences from QRadar along with all the additional data about the offenses. The data from QRadar is populated into XSOAR incident fields providing the XSOAR analyst with all the information about the incident just by performing a fetch. 

Using the commands in the integration, you can leverage what the QRadar API has to offer, such as:
- Editing objects
- Getting object lists
- Adding notes
Basically, you can perform tasks that a user would need to do manually in the QRadar UI or would need to provide automations to do.

## How to use this pack?
Follow the steps provided in this [article](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-tutorials/tutorials/ingest-incidents-from-a-siem.html) to configure fetching offenses from QRadar to XSOAR.
