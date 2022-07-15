Integrate with Logz.io Cloud SIEM to automatically remediate security incidents identified by Logz.io and increase observability into incident details.
The integration allows Cortex XSOAR users to automatically remediate incidents identified by Logz.io Cloud SIEM using Cortex XSOAR Playbooks.
In addition, users can query Logz.io directly from Cortex XSOAR to investigate open questions or retrieve the logs responsible for triggering security rules.

##### What does this pack do?
**Logz.io Handle Alert:** used to handle alerts retrieved from Logz.io.
The playbook will retrieve the related events that generated the alert using the logzio-get-logs-by-event-id command
**Logzio_Indicator_Hunting:** This playbook queries Logz.io in order to hunt indicators such as 
- File Hashes 
- IP Addresses 
- Domains 
- URLS 
And outputs the related users, IP addresses, host names for the indicators searched.

As part of this pack you will also get out of the box incident types and fields mapping for the information coming from Logz.io Cloud SIEM which are adjustable and customisable.

For more information. Visit our
[Logz.io Website] (https://logz.io)
[Logz.io & Cortex XSOAR Integration doc] (https://docs.logz.io/user-guide/cloud-siem/xsoar-integration/)
