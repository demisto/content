# SOC CrowdStrike Falcon – Product Enhancement Configuration

This repository contains configuration assets and playbooks that enhance the CrowdStrike Falcon integration within Cortex XSIAM. These enhancements improve visibility, triage workflows, and automation by aligning Falcon alerts to the SOC Framework and MITRE ATT&CK tactics.

## 📌 Overview

CrowdStrike Falcon is a valuable telemetry source that produces high-fidelity alerts, but often requires tuning and enrichment to integrate cleanly into XSIAM workflows. This enhancement package enables:

- A custom layout rule for Falcon alerts
- MITRE tactic–aligned correlation rules for early grouping
- A fallback correlation rule for unmapped alerts

## 🚀 Getting Started

### Step 1: Create a Layout Rule for CrowdStrike Alerts

To improve the analyst experience and prioritize Falcon-specific fields:

Go To: **Settings → Configurations → Object Setup → Layout Rules**

- **Rule Name:** `CrowdStrike Alert Layout`
- **Entity Type:** Alert
- **Filter Criteria:**
  - Alert Source: Equals `CrowdStrike Falcon`
- **Action:**
  - Assign a custom alert layout optimized for Falcon alert data

> This layout should surface key fields like `CommandLine`, `FilePath`, `Sensor ID`, `Tactic`, `Technique`, and `Severity`.

#### 🖼️ Layout Rule Visualization

![CrowdStrike Layout Rules](https://github.com/Palo-Cortex/soc-crowdstrike-falcon/blob/main/images/crowdstrikelayoutrules.png)

> This layout rule ensures the most relevant fields are presented to analysts working Falcon-related alerts.

### Step 2: Enable MITRE Tactic–Based Correlation Rules

Enable correlation rules that group Falcon alerts into incidents based on their mapped MITRE ATT&CK tactic.

Go To: **Detection & Correlation → Correlation Rules**

Enable the following rules:

| Correlation Rule Name                      | MITRE Tactic                   |
|--------------------------------------------|--------------------------------|
| `CrowdStrike – Initial Access Correlation` | `TA0001 - Initial Access`      |
| `CrowdStrike – Execution Correlation`      | `TA0002 - Execution`           |
| `CrowdStrike – Persistence Correlation`    | `TA0003 - Persistence`         |
| `CrowdStrike – Privilege Escalation Correlation` | `TA0004 - Privilege Escalation` |
| `CrowdStrike – Defense Evasion Correlation`| `TA0005 - Defense Evasion`     |
| *(...continue for all relevant tactics)*   |                                |

> These rules use fields like `MITRE Tactic`, `cmdline`, and `host` to group relevant alerts into single, actionable incidents.

#### 🖼️ Correlation Rules Visualization

![CrowdStrike Correlation Rules](https://github.com/Palo-Cortex/soc-crowdstrike-falcon/blob/main/images/crowdstrikerules.png)

> This visualization maps how Falcon alerts are organized by tactic to drive meaningful triage and response workflows.

### Step 3: Enable No MITRE Tactic Correlation Rule

Some CrowdStrike alerts may lack MITRE mappings. Enable a fallback rule to handle these:

- **Rule Name:** `CrowdStrike – No MITRE Tactic`
- **Logic:**
  - `MTIRE Tactic` is null or not present
  - Group by fields such as `Sensor ID`, `Host`, or `Process Name`

> This ensures unmapped alerts are still grouped effectively for investigation and triage.

## 🧠 Why This Matters

These configurations align with XSIAM FieldOps Model pillars:

| Value Driver          | Capability Delivered                                              |
|----------------------|-------------------------------------------------------------------|
| Transformation        | Analysts see clean, consistent layouts across all Falcon alerts   |
| Risk & Resiliency     | MITRE alignment improves coverage and detection granularity       |
| Automation & Efficacy | Alert correlation minimizes noise and drives automated workflows  |

## 🧪 Validation Tips

- Use **BYOS MITRE Lab** to simulate Falcon alerts across different tactics
- Confirm layout rules apply only to Falcon alerts
- Ensure correlation rules create grouped incidents per tactic or fallback logic
- Monitor grouped incidents in the **Value Dashboard** to assess rule effectiveness

## 🧩 Dependencies

- Custom Alert Layout (JSON layout file)
- SOC Optimization Framework (for scoring and triage)

---

For questions or help extending this pack, reach out to your Palo Alto Networks Field team or SOC Framework maintainers.
