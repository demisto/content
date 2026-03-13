# SOC Trend Micro Vision One – Product Enhancement Configuration

This repository contains configuration assets and playbooks that enhance the **Trend Micro Vision One** integration within Cortex XSIAM.  
These enhancements improve visibility, triage workflows, and automation by aligning Vision One alerts to the SOC Framework and MITRE ATT&CK tactics.

---

## 📌 Overview

Trend Micro Vision One provides advanced XDR telemetry across endpoint, email, network, and identity sources.  
However, its alerts often require normalization, field mapping, and correlation to fully align with XSIAM workflows.

This enhancement package enables:

- A custom layout rule for Vision One alerts
- MITRE tactic–aligned correlation rules for early incident grouping
- A fallback correlation rule for unmapped or generic alerts

---

## 🚀 Getting Started

### Step 1: Create a Layout Rule for Vision One Alerts

To improve analyst efficiency and ensure consistent presentation of Vision One data:

Go To: **Settings → Configurations → Object Setup → Issues → Layout Rules**

- **Rule Name:** `Trend Micro Vision One Alert Layout`
- **Filter Criteria:**
  - Alert Source: Equals `Tags: DS:Trend Micro Vision One V3`
- **Layout To Display:**
  - Layout: Equals `SOC Trend Micro Vision One IR`

#### 🖼️ Layout Rule Visualization

![Vision One Layout Rules](images/TrendVisionOneLayout.png)

> This rule ensures that analysts immediately see the most relevant Vision One alert data in context.

---

### Step 2: Enable MITRE Tactic–Based Correlation Rules

Enable correlation rules that group Vision One alerts into incidents based on their mapped MITRE ATT&CK tactic.

Go To: **Detection & Correlation → Correlation Rules**

Enable the following rules (Disable any default rules from Integration Install):

![Vision One Layout Rules](images/TrendVisionCorrelations.png)

---

## 🧠 Why This Matters

These configurations align directly with the **XSIAM FieldOps Model** and **SOC Optimization Framework**, delivering:

| Value Driver          | Capability Delivered                                              |
|------------------------|-------------------------------------------------------------------|
| Transformation         | Consistent, enriched layouts for all Vision One alerts            |
| Risk & Resiliency      | MITRE mapping improves visibility and detection coverage          |
| Automation & Efficacy  | Correlation reduces alert fatigue and improves investigation speed |

---

For questions or help extending this pack, contact your **Palo Alto Networks Field Team** or the **SOC Framework maintainers**.
