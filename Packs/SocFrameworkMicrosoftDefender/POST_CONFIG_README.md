# SOC Microsoft Defender – Product Enhancement Configuration

This repository contains configuration assets and playbooks that enhance the **Microsoft Defender** integration within Cortex XSIAM.  
These enhancements improve visibility, triage workflows, and automation by aligning Microsoft Defender alerts to the SOC Framework and MITRE ATT&CK tactics.

---

## 📌 Overview

Microsoft Defender provides advanced XDR telemetry across endpoint, email, network, and identity sources.  
However, its alerts often require normalization, field mapping, and correlation to fully align with XSIAM workflows.

This enhancement package enables:

- A custom layout rule for Microsoft Defender alerts
- MITRE tactic–aligned correlation rules for early incident grouping
- A fallback correlation rule for unmapped or generic alerts

---

## 🚀 Getting Started

### Step 1: Create a Layout Rule for Microsoft Defender Alerts

To improve analyst efficiency and ensure consistent presentation of Microsoft Defender data:

Go To: **Settings → Configurations → Object Setup → Issues → Layout Rules**

- **Rule Name:** `Microsoft Defender Alert Layout`
- **Filter Criteria:**
  - Alert Source: Equals `Tags: DS:Microsoft Graph`
- **Layout To Display:**
  - Layout: Equals `SOC Microsoft Defender IR`

#### 🖼️ Layout Rule Visualization

![Microsoft Defender Layout Rules](images/LayoutRule.png)

> This rule ensures that analysts immediately see the most relevant Microsoft Defender alert data in context.

---

### Step 2: Enable MITRE Tactic–Based Correlation Rules

Enable correlation rules that group Microsoft Defender alerts into incidents based on their mapped MITRE ATT&CK tactic.

Go To: **Detection & Correlation → Correlation Rules**

Enable the following rules (Disable any default rules from Integration Install):

![Microsoft Defender Layout Rules](images/Correlations.png)

---

## 🧠 Why This Matters

These configurations align directly with the **XSIAM FieldOps Model** and **SOC Optimization Framework**, delivering:

| Value Driver          | Capability Delivered                                              |
|------------------------|-------------------------------------------------------------------|
| Transformation         | Consistent, enriched layouts for all Microsoft Defender alerts            |
| Risk & Resiliency      | MITRE mapping improves visibility and detection coverage          |
| Automation & Efficacy  | Correlation reduces alert fatigue and improves investigation speed |

---

For questions or help extending this pack, contact your **Palo Alto Networks Field Team** or the **SOC Framework maintainers**.
