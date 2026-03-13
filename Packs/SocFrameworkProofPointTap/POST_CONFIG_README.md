# SOC-Proofpoint-TAP Content Pack for Cortex XSIAM

This repository contains the **SOC-Proofpoint-TAP** content pack for Palo Alto Networks Cortex XSIAM. It enables effective incident handling and visibility for Proofpoint TAP v2 alerts by providing layout customizations and detection rule guidance.

---

## 📦 What's Included

- Incident Layouts:
  - `Proofpoint - Message Delivered`
  - `Proofpoint - Click Permitted`
- Layout Rules to dynamically assign layouts based on alert metadata
- Sample Data Model Rules syntax for use in XSIAM
- Supporting configurations to route and visualize Proofpoint TAP v2 alerts

---

## ✅ Prerequisites

- Cortex XSIAM tenant
- Ingested and parsed data from **Proofpoint TAP v2** (via Broker VM, API, or other integrations)
- `SOC Proofpoint TAP` content pack installed

---

## 🛠️ Additional Manual Steps Post-Installation


### 1. Configure the Proofpoint TAP Integration Instances
1. Navigate to **Settings → Configurations → Data Collection → Automation & Feed Integration**
2. Expand the Proofpoint TAP instance dropdown 
3. Click on the gear next to the _Proofpoint TAP v2_Clicks_Permitted_ and _Proofpoint TAP v2_Messages_Delivered_
4. Update the integration instances' configurations for the following form fields: 
   1. Server URL
   2. Service Principal
   3. Password
   
5. Test and save the integration instance configurations
6. **Enable** the instances


### 2. Disable System Proofpoint Correlation Rules
1. Navigate to **Detection & Threat Intel → Correlations**
2. Filter the Correlation Rules _Name_ column for “Proofpoint”
3. Right Click on **Proofpoint TAP v2 Alerts (automatically generated)**
4. Choose _Disable_


### 3. Verify the Proofpoint Correlation Rules 
Once traffic starts flowing to the proofpoint_tap_v2_generic_alert_raw dataset, you will need to verify the correlation rule as the following: 

1. Navigate to **Detection & Threat Intel → Correlations**
2. Filter the Correlation Rules Name column for “Proofpoint”
3. Right-click the following rules that apply to your tenant:
   1. Production Proofpoint TAP + CrowdStrike - Messages Delivered
   2. Production Proofpoint TAP - Clicks Permitted
   3. Production Proofpoint TAP + CrowdStrike - Clicks Permitted
   4. Production Proofpoint TAP - Messages Delivered
4. Click Preview Rule
5. Verify the Alert Suppression > Fields keys are not throwing errors

### 4. (Recommended) Configure Starred Alerts - ProofPoint Clicks Permitted
Incidents that are not marked with a star are automatically triaged using `JOB_-_Triage_Incidents.yml`.
This ensures that high-volume, low-risk alerts are handled without manual intervention. These are the recommended starred
alerts for this pack.

1. Go to **Incident Response → Automation → Incident Configuration → Starred Alerts**
2. Config The Proofpoint Clicks Permitted as below

   1. Configuration Name: _Proofpoint Clicks Permitted_
   2. Alert Filter: _**alert domain** = Security **AND alert name** contains Click Permitted **AND tags =** DS:Proofpoint TAP v2_


