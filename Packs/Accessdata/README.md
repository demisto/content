New and advanced forms of cybersecurity threats are continually evolving to target enterprises.  In the event of a cybersecurity incident, rapid evidence capture and response is the key to quickly patching an enterprise’s vulnerabilities and preventing another attack.  With the integration between Cortex XSOAR, Exterro FTK Connect and FTK Enterprise, users can now leverage Cortex XSOAR's security orchestration and automation capabilities to trigger the immediate capture and preservation of endpoint evidence by FTK Enterprise, which is crucial for incident investigation and recovery.


Preservation and the ability to provide defensible & verifiable evidence of how a breach occurred is critically important for adhering to regulatory standards, insurance requirements, and demonstrating compliance.  This automated integration saves time during all stages of incident response, from triage and investigation to post-analysis and full recovery, by preserving rich forensic data related to the root cause of the breach.

##### What does this pack do?

Exterro’s FTK Connect features a robust API that enables a secure connection between Cortex XSOAR and FTK Enterprise.
When Cortex XSOAR detects an attack, it sends an alert that is received by the FTK Connect API, which initiates the playbook where FTK Enterprise automatically initiates a collection job on the endpoint.

Automatically preserve electronic evidence by initiating the immediate collection of data at the designated endpoint, using automated incident playbooks.
Ensure evidence is collected and preserved in a legally defensible manner for full data integrity with forensically sound collection capabilities using a single, secure back-end database.
Reduce data movement between platforms to avoid data spoliation with seamless handoff from incident detection to analysis and response. 

- Learn more about [FTK Enterprise](https://www.exterro.com/ftk-enterprise)

- Learn more about the [FTK Connect API](https://www.exterro.com/ftk-api)

2 Major Use Cases:

1.   Data Exfiltration
Once potential data exfiltration is identified from inside the network, a Cortex XSOAR playbook can automatically trigger the Exterro restful API to instantly capture a complete list of all processes currently running on the suspected machine, and their associated DLL files.  
From here, you can identify any processes that are unauthorized, and invoke Exterro to automatically remediate them.
An automatic job collection is then initiated by FTK Enterprise at this specified endpoint.
The Cortex XSOAR and Exterro integration automates this time-intensive process that would normally need to be completed manually.


2.   Automated Memory Dump
Acquiring a memory dump or drive scan from a compromised endpoint in a suspected internal breach is key, especially before the evidence is lost.

By using an automated Cortex XSOAR playbook and the AccessData API to initiate collection of a memory dump, the analysis can take place without alerting the suspecting individual, i.e. covert acquisition.
Once the memory dump is collected, you can proceed with the investigation and recovery of saved passwords, open network connections, or recover an entire webpage, which may only be stored in memory, such as a web page viewed in Chrome Incognito.
