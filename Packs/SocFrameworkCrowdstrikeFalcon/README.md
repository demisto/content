# 🛡️ SOC CrowdStrike Falcon Integration Enhancement for Cortex XSIAM

This repository enhances the native CrowdStrike Falcon integration within Palo Alto Networks Cortex XSIAM. It provides layouts, correlation rules, mappers, and data model extensions to optimize threat visibility and automate response actions within a SOC workflow.

---

## ⚙️ Prerequisites

- Configure **CrowdStrike Falcon** integration via **Marketplace**
- If using **CrowdStrike Platform** integration, **disable Alert Fetch**

---

## 🚀 Purpose

This pack enables Cortex XSIAM to more effectively operationalize CrowdStrike Falcon telemetry by:

- 📊 Centralizing endpoint threat and detection data.
- ⚙️ Automating detection, triage, and response for endpoint-related incidents.
- 🔁 Enriching alerts with actionable context and reducing the need to pivot tools.
- 🧩 Enabling correlation with identity, email, and network telemetry.

---

## 📦 What's Included

| Component        | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| **Layouts**       | Analyst-centric views showing CrowdStrike event details, detections, and host context. |
| **Correlation Rules** | Rules for identifying lateral movement, hands-on-keyboard activity, and malware execution. |
| **Data Models**   | XDM schema extensions aligned to Falcon detection and event fields. |
| **Automation Scripts** |  
| `displayCrowdStrikeEvidence_xsiam` | Displays raw alert record cleanly in layout tab/dynamic sections. |
| `displayCrowdStrikeHostRecord_xsiam` | Renders full host record in layout tab/dynamic sections. |
| `displayCrowdStrikeHostStatus_xsiam` | Shows host status in a structured format inside layout sections. |

---

## 🧠 Analyst Benefits

- Improved endpoint visibility within Cortex XSIAM.
- Context-aware enrichment across SOC alerts.
- Faster threat detection and reduced MTTR.
- Direct action capability via Falcon integration.

> 🔄 **Compatible with the [SOC Optimization Framework](https://github.com/Palo-Cortex/soc-optimization-framework)** for standardized detection and response across data sources.

---

## 🔗 Use Case Compatibility

- **Malware Investigation**
- **Lateral Movement Detection**
- **Privilege Escalation Monitoring**
- **Automated Host Containment**

---

## ⚙️ Integration Requirements

- Cortex XSIAM tenant
- **CrowdStrike Falcon** data ingested via XDR integration or broker
- This pack handles all normalization via mappers and model extensions

---

## 🛠️ How to Use

1. Clone this repository.
2. Use the [Demisto “XSOAR” SDK](https://github.com/demisto/demisto-sdk) to upload content to Cortex XSIAM.
3. Choose and enable correlation rules based on your detection objectives.
4. Deploy and validate layouts, and models.
5. Tune as needed for your threat model and operational needs.

---

## 🛠 Installation & Configuration

### 📦 Installing the Pack into Cortex XSIAM

To install this content pack using the [Demisto SDK](https://github.com/demisto/demisto-sdk), run the following command:

demisto-sdk upload -x -z -i ./Packs/soc-crowdstrike-falcon

> **Note:**  
> - `-x` ensures the pack is zipped before upload.  
> - `-z` uploads the zipped pack.  
> - Adjust the path (`-i`) as needed to match your local directory structure.

Make sure your environment is properly configured with the XSIAM host and API key by using either:

- A `.env` file, **or**
- Setting the following environment variables:
  - `DEMISTO_BASE_URL`
  - `DEMISTO_API_KEY`
  - `XSIAM_AUTH_ID`

---

### 🧩 Post-Installation Configuration

After uploading the pack, complete the following steps to ensure alerts are displayed properly:

1. Navigate to **Settings > Alert Layout Rules** in XSIAM.
2. Click **Add Layout Rule**.
3. Configure the rule with the following values:
   - **Rule Name**: `CrowdStrike`
   - **Layout to Display**: `CrowdStrike Endpoint Alert Layout`
   - **Alert Type**: `CrowdStrikeFalcon_XSIAM`

> ⚠️ **Important:** The `Alert Type` must exactly match the dataset name created by the integration:  
> `CrowdStrikeFalcon_XSIAM`

---

## 🤝 Contributing

Contributions are welcome via pull requests or issues.

---

## 📚 Related Resources

- [CrowdStrike Falcon API Docs](https://falcon.crowdstrike.com/support/documentation)
- [Cortex XSIAM Docs](https://docs.paloaltonetworks.com/cortex/cortex-xsiam)
- [SOC Optimization Framework](https://github.com/Palo-Cortex/soc-optimization-framework)

---

## 🏷️ Tags

`CrowdStrike` `Falcon` `Endpoint` `Malware` `XSIAM` `SOC` `Automation`

Once configured, alerts ingested from CrowdStrike Falcon will automatically use the custom layout defined in this pack.
