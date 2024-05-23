# HarfangLab EDR

This connector allows to fetch security events from a HarfangLab EDR Manager and manage the incident response. 

It is shipped with:

  * an integration with 60+ commands/tasks, 
  * an alert management playbook including 20+ sub-playbooks,
  * several Threat Intelligence Management playbooks that allows to hunt for IOCs in the EDR, manually review the IOC sightings and then put the IOCs into detection in the EDR,
  * an alert type along with its associated incident mapper,
  * a specific alert layout tailored to HarfangLab EDR alerts.

The alert management playbook illustrates several steps of a typical incident response with forensics activities:

  1. Endpoint isolation
  2. Forensics data collection 
  3. Raw artifacts collection
  4. Agent reconnection
  5. Case closing
