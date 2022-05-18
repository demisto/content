This OT Security pack is created to help you to automate the incident response and threat hunting processes in your Operations and ICS environment.

# Pack Overview
![](https://raw.githubusercontent.com/demisto/content/master/Packs/OTSecurity/doc_files/OTSecurityEnvironment.png)

Cortex XSOAR helps to automate OT incidents and alerts response by gathering all relevant data, even from sources that may seem unrelated,
allowing for the buildout of playbooks that cater to the particular automation needs of an ICS’s operational requirements. It also provides bot-aided war rooms where
security analysts and SMEs can safely and securely collaborate on the best course of action. Most importantly, Cortex XSOAR provides automatic documentation of all steps and
processes taken to validate and resolve issues or incidents, creating a knowledge warehouse for first responders. 

# Pack Roadmap
Below are sample types OT investigation that his pack will focus on:

- __Initial Access__
    - Supply Chain Compromise
    ![](https://raw.githubusercontent.com/demisto/content/master/Packs/OTSecurity/doc_files/ATT%26CK%20T862.png)

    - Data Historian Compromise
    ![](https://raw.githubusercontent.com/demisto/content/master/Packs/OTSecurity/doc_files/ATT%26CK%20T810.png)

- __Execution and Persistence__
    - Unauthorized Program State Alteration
    ![](https://raw.githubusercontent.com/demisto/content/master/Packs/OTSecurity/doc_files/ATT%26CK%20T875.png)
    - Project File Infection
    ![](https://raw.githubusercontent.com/demisto/content/master/Packs/OTSecurity/doc_files/ATT%26CK%20T873.png)
- __Evasion__
    - Rogue Device Detected
    ![](https://raw.githubusercontent.com/demisto/content/master/Packs/OTSecurity/doc_files/ATT%26CK%20T848.png)
    - Rootkits Detected
    ![](https://raw.githubusercontent.com/demisto/content/master/Packs/OTSecurity/doc_files/ATT%26CK%20T851.png)
- __Discovery__
    - I/O Module Discovery
    ![](https://raw.githubusercontent.com/demisto/content/master/Packs/OTSecurity/doc_files/ATT%26CK%20T851.png)
    - Network Service Scanning
    ![](https://raw.githubusercontent.com/demisto/content/master/Packs/OTSecurity/doc_files/ATT%26CK%20T824.png)
- __Lateral Movement__
    - Default Credentials Login
    - Unautherized Remote File Copy
- __Collection__
    - Process State Dump
    - Unautherized Program Upload
- __Command and Control__
    - Proxied Connection Detected
    - Protocol Anomaly Detected
- __Inhibit ICS Function__
    - Activate Firmware Update Mode
    - Unauthorized Program State Alteration

XSOAR content included in this pack will be built based on our integrations with OT security controls that include:
- __Network Segmentation Firewalls From__
    - Palo Alto Networks
    - FortiGate
    - Cisco
    - Calroty
- __Network Access Control From__
    - Cisco
    - Forsecout
- __Network Visibility From__
    - Nozomi
    - ScadaFence
- __Endpoint Security From__
    - Kaspersky
    - Symantec
- __SIEM From__
    - IBM
    - Logrhythem
    - Splunk
- __Vulnerability Management From__
    - Tenable

# XSOAR in Isolated OT Environment
![](https://raw.githubusercontent.com/demisto/content/master/Packs/OTSecurity/doc_files/IsolatedDeployment.png)
XSOAR provides the ability to have a production instance running in an isolated OT environment, with a jumb host access to a local repository that stores the content updates, for more details:
https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-2/cortex-xsoar-admin/remote-repository/configure-a-remote-repository-on-a-development-machine.html

