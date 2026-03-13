# 🛡️ SOC Microsoft Defender Integration Enhancement for Cortex XSIAM

This repository delivers enhanced integration for Microsoft Defender within Cortex XSIAM. It includes layouts, correlation rules, mappers, and data model updates to support deep visibility and automated response to Windows-based threats.

---

## 🚀 Purpose

This pack enables SOC teams to leverage Defender for Endpoint telemetry in Cortex XSIAM by:

- 🖥️ Aggregating endpoint alerts, indicators, and actions in one place.
- 🧠 Enabling enriched detection and alert correlation across the SOC toolset.
- 🔄 Automating response workflows for common Windows threats.
- 📈 Supporting detection of ransomware, persistence, and post-exploitation behavior.

---

## ⚙️ Prerequisites

- Configure **two Microsoft integrations**:
  - **O365 Data Source**
    - Ensure **alert fetch** is enabled via **Microsoft Graph Alerts v2**
![AlertsIntegration.png](images/AlertsIntegration.png)
  - **Microsoft Defender for Endpoint** (from Marketplace)
    - Used for **automation commands only**
![ActionsIntegration.png](images/ActionsIntegration.png)
---

## 📦 What's Included

| Component        | Description                                                                 |
|------------------|-----------------------------------------------------------------------------|
| **Layouts**       | Analyst-focused dashboards showing Defender alerts, evidence, and response history. |
| **Correlation Rules** | Patterns identifying malware behavior, credential theft, and suspicious process chains. |
| **Automation Scripts** |  
| `displayDefenderEvidence_xsiam` | Displays raw alert record cleanly in layout tab/dynamic sections. |
| `displayDefenderHostRecord_xsiam` | Renders full host record in layout tab/dynamic sections. |
| `displayDefenderHostStatus_xsiam` | Shows host status in a structured format inside layout sections. |

## 🧠 Analyst Benefits

- Centralized Defender telemetry in XSIAM for faster triage.
- Fewer context switches with integrated enrichment and automation.
- Improved detection accuracy via cross-source correlation.
- Streamlined playbook-driven containment and investigation.

> 🔄 **Compatible with the [SOC Optimization Framework](https://github.com/Palo-Cortex/soc-optimization-framework)** to drive repeatable and measurable SOC operations.

---

## 🔗 Use Case Compatibility

- **Windows Endpoint Threat Detection**
- **Credential Dumping and Abuse**
- **Suspicious Process Monitoring**
- **Automated Host Isolation**

---

## ⚙️ Integration Requirements

- Cortex XSIAM tenant
- **Microsoft Defender for Endpoint** telemetry ingested (via native or broker integration)

---

## 🛠️ How to Use

1. Clone this repository.
2. Use the [Demisto “XSOAR” SDK](https://github.com/demisto/demisto-sdk) to upload the content into XSIAM.
3. Select and deploy correlation rules relevant to your use case.
4. Load supporting mappers, and layouts.
5. Refine detection logic and response pathways as needed.

---

## 🤝 Contributing

We welcome contributions via pull requests or GitHub issues.

---

## 📚 Related Resources

- [Microsoft Defender API Docs](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/)
- [Cortex XSIAM Docs](https://docs.paloaltonetworks.com/cortex/cortex-xsiam)
- [SOC Optimization Framework](https://github.com/Palo-Cortex/soc-optimization-framework)

---

## 🏷️ Tags

`Microsoft Defender` `Windows Security` `Endpoint` `XSIAM` `SOC` `Automation` `Detection Engineering`

