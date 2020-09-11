#Product/Integration Overview
XMCyber continuously finds attack vectors to critical assets. This integration exposes the attack vectors and the techinques found by XMCyber to indicate endpoints, users, files, etc that pose high risk to the organization. In addition, Demisto’s other integrations can feed XMCyber with knowledge about potential breach points and critical assets with which to run dynamic and accurate scenarios.

##Use Cases
- New attack path to a critical asset triggers alerts and options to quarantine/disconnect
- New attack technique triggers alerts and options to change policy, and scan endpoints
- Bad reputation, detections, etc are gathered from other security controls to dynamically set the breach points in XMCyber scenarios
- Lists of critical assets in other solutions are automatically imported and updated in XMCyber
- New incidents in Demisto will query XMCyber about the attack paths of the entities involved in the incident. XMCyber will enrich the incident with that knowledge.

##Playbooks
*Handle-XMCyber-New-Asset-Attack-Path*  
Used to notify analyst of new risk to critical assets. Calls “XMCyber-Asset-Attack-Path-List” on the last 3 months and compares to the current attack paths. If an attack path to an asset is found for the first time in the current paths it initiates a notification process. Once the alert has been managed by the SOC, it is marked as closed.

*Handle-XMCyber-New-Technique*  
Used to notify analyst of attack technique prevalent in the organization. Calls “XMCyber-Techniques-List” on the last 3 months and compares to the current techniques. If a technique is found for the first time in the current list the playbook initiates a notification process. Once the alert has been managed by the SOC, it is marked as closed.

*XMCyber-Breachpoint-Incidents*  
Collect incidents from Endpoint products, such as CrowdStrike, and based on their severity calls on “XMCyber-Breachpoint-Update” with the latest list of hosts with severe incidents. Once the list is updated a new campaign will run in XMCyber and the results will affect choke points and “pressure” score of entities.

*XMCyber-Critical-Assets-Import*  
Collect lists of critical assets from products that maintain grouping and categorization of the organization. Calls on “XMCyber-Critical-Asset-Add” with the latest list of hosts. Once the list is updated a new campaign will run in XMCyber and the results will affect choke points and “pressure” score of entities.

*XMCyber-Incident-Attack-Paths*  
When a new incidents is generated with entities such as hostname, user, or file this playbook will query XMCyber about the attack paths to and from with the “XMCyber-Attack-Paths-To-Entity” and “XMCyber-Attack-Paths-From-Entity”. XMCyber will enrich the incident with that knowledge in the form of evidence.
