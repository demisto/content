# 🛡️ SOC Proofpoint TAP Integration Enhancement for Cortex XSIAM

This repository supplements the native Proofpoint Threat Protection (TAP) integration within Palo Alto Networks Cortex XSIAM. It provides a comprehensive set of enhancements designed to streamline the analyst experience, enrich email threat context, and reduce investigation time by consolidating relevant Proofpoint data into a single workspace.

---

## 🚀 Purpose

The goal of this repository is to extend the value of the out-of-the-box Proofpoint TAP integration by offering an end-to-end solution that enables:

- 📊 Unified visibility of email threat data.
- 🔁 Seamless interaction between Cortex XSIAM and Proofpoint.
- ⚙️ Automation of common SOC workflows for email-based threats.
- 👨‍💻 Analyst-friendly layouts that eliminate the need to pivot between tools.

---

## 📦 What's Included

This repository contains packaged content that accelerates Proofpoint TAP integration within a SOC workflow, including:

| Component           | Description                                                                 |
|---------------------|-----------------------------------------------------------------------------|
| **Layouts**         | Custom incident and alert views that display all relevant Proofpoint threat context. |
| **Correlation Rules** | Two correlation rules: one based solely on Proofpoint data, and another that enriches Proofpoint alerts with CrowdStrike endpoint telemetry. |
| **Mappers**         | Field mapping templates that normalize Proofpoint TAP events into Cortex XSIAM’s schema. |
| **Data Models**     | XDM schema extensions tailored to Proofpoint's alert and message data structures. |

---

## 🧠 Analyst Benefits

By deploying this content pack, SOC teams can:

- Reduce investigation friction by centralizing Proofpoint alert data in Cortex XSIAM.
- Minimize tool-switching fatigue by leveraging automated lookups and response actions directly within incidents.
- Accelerate triage and response with actionable context on threats, users, recipients, URLs, attachments, and more.
- Enable faster Mean Time to Detect (MTTD) and Mean Time to Respond (MTTR) by correlating TAP alerts with endpoint, identity, and network data in XSIAM.

> 🔄 **Compatible with the [SOC Optimization Framework](https://github.com/Palo-Cortex/soc-optimization-framework)** to drive scalable, repeatable, and measurable detection and response patterns.

---

## 🔗 Use Case Compatibility

This pack is intended for the following SOC use cases:

- **Email Threat Investigation and Response**
- **Phishing Detection and Triage**
- **User-Centric Threat Hunting**
- **SOC Workflow Automation**

---

## ⚙️ Integration Requirements

Before using this pack, ensure the following:

- Cortex XSIAM tenant is active and has:
  - **Proofpoint TAP integration** configured and operational

> ✅ **Note**: Data from Proofpoint TAP is automatically normalized into the XDM schema through the mappers included in this pack. No additional normalization setup is required.

---

## 🛠️ How to Use

1. Clone this repository to your local environment.
2. Use the [Demisto “XSOAR” SDK](https://github.com/demisto/demisto-sdk) to upload the content into your Cortex XSIAM tenant. Ex: `demisto-sdk upload -x -z -i ../Packs/soc-proofpoint-tap`
3. Choose the correlation rule(s) most applicable to your environment:
   - **Proofpoint Only**: Detects threats based solely on TAP telemetry.
   - **Proofpoint + CrowdStrike**: Enriches TAP alerts with endpoint context for higher fidelity detection.
4. Deploy layouts, mappers, and data models using the Content Management interface.
5. Tune correlation rules as needed to fit your threat model and data sources.

---

## 🤝 Contributing

Contributions to improve or extend this pack are welcome. Please submit a pull request or open an issue with suggestions, bugs, or feature requests.

---

## 📚 Related Resources

- [Proofpoint TAP API Documentation](https://threatinsight.proofpoint.com)
- [Cortex XSIAM Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xsiam)
- [SOC Optimization Framework](https://github.com/Palo-Cortex/soc-optimization-framework)
- [Email Threat Playbooks (SOC Phishing)](https://github.com/Palo-Cortex/soc-phishing)

---

## 🏷️ Tags

`Proofpoint` `TAP` `Email Security` `Phishing` `XSIAM` `SOC` `Automation` `Threat Detection`
