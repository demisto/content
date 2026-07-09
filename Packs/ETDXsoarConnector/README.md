# ETD XSOAR Connector


## Overview


The ETD XSOAR Connector integrates Cisco Email Threat Defense (ETD) with Cortex XSOAR. The integration fetches ETD message events, creates incidents for malicious and suspicious emails, and provides remediation and reclassification capabilities through Cisco ETD APIs.



## Use Cases


* Fetch malicious and suspicious email events from Cisco ETD.

* Create incidents in Cortex XSOAR for ETD email threats.

* Reclassify email verdicts.

* Remediate emails by moving messages to different folders.

* Support analyst-driven email investigation and response workflows.


## What does this pack do?


### Integration

ETDXsoarConnector fetches Cisco ETD message events and creates incidents in Cortex XSOAR.

#### ETDXsoarConnector

Fetches Cisco ETD message events and creates incidents in Cortex XSOAR.

### Incident Type

#### ETD Malicious Email

Custom incident type used for Cisco ETD email incidents.


### Incident Fields

#### ETD Message ID

Stores the Cisco ETD Message ID required for email remediation and reclassification actions.



### Playbook



#### ETD Email Reclassification and Remediation**

Allows analysts to review ETD email incidents and perform remediation and reclassification actions.

#### Supported Reclassification Actions

* bec

* scam

* malicious

* phishing

* spam

* graymail

* neutral

#### Supported Remediation Actions

* quarantine

* inbox

* junk

* trash

* delete

## Requirements

### Cortex XSOAR Version

* 6.10.0 

### Cisco ETD Requirements

* Cisco Email Threat Defense tenant

* Valid API credentials

* API access enabled



## Workflow



### Incident Creation



1. Cisco ETD generates a message event.

2. The integration fetches the event.

3. Cortex XSOAR creates an ETD Malicious Email incident.



### Incident Response



1. Analyst opens the incident.

2. Analyst runs the ETD Email Reclassification and Remediation playbook.

3. Analyst selects a new verdict and remediation action.

4. Cortex XSOAR submits the action to Cisco ETD.



## Author

Cortex XSOAR  
