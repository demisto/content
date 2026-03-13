# 🛡️ Cortex XSIAM – CrowdStrike Falcon Integration Setup

Enhances the native CrowdStrike Falcon integration in Cortex XSIAM with tailored layouts, automation support, dashboards, and correlation rules to improve threat visibility and SOC response efficiency.

---

## 🚀 Configuration Steps

### 1. Configure the CrowdStrike Falcon Integration Instance
1. Navigate to **Settings → Configurations → Data Collection → Automation & Feed Integration**
2. Expand the CrowdStrike Falcon instance dropdown 
3. Click on the gear next to the _CrowdstrikeFalcon_Detections_Incidents_
4. Update the integration instance’s configuration for the following form fields: 
   1. Server URL
   2. Client ID
   3. Secret
   
5. Test and save the integration instance configuration
6. **Enable** the instance

### Troubleshooting
The SOC CrowdStrike Product Enhancements will not install unless the crowdstrike_falcon_event_raw dataset exits. The modeling requires the dataset to exist.