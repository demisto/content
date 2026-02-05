## Cyfirma DeCYFIR Content Pack

CYFIRMA’s core platform, DeCYFIR, combines cyber threat intelligence with attack surface discovery and digital risk protection to deliver predictive, personalized, contextual, outside-in, and multi-layered cyber-intelligence.
With DeCYFIR’s APIs, security teams obtain a complete view of their external threat landscape and receive actionable insights to ensure their cybersecurity posture is robust, resilient, and able to counter emerging cyber threats.

#### This packs empowers security teams with the following capabilities

- Monitor your entire external attack surfaces as they emerge.
- Gain knowledge of vulnerabilities and understand the threat actors, campaigns, attack methods which could be used by adversaries.
- Stay informed of data breach/leaks and this includes company email addresses, intellectual property info, confidential data.
- Be alerted to impersonation of company domains and executives across public and social platforms.
- Prioritize remedial actions with insights from external threat landscape.de
- Use the insights to expedite threat hunting and accelerate incident response activities.

<~XSOAR>

**Note:**
Support and maintenance for this integration is provided by **[Cyfirma](https://www.cyfirma.com)**.
Please contact us for more details on this email **_contact@cyfirma.com_**.

</~XSOAR>

<~XSIAM>

Collects event logs from DeCYFIR for ingestion into Cortex XSIAM.

Once configured, the integration periodically fetches event logs from DeCYFIR’s APIs and sends them to **Cortex XSIAM** for ingestion, normalization and analysis.

- Events are fetched in real time (starting from the moment the integration is enabled).

- Each event type (`Access Logs`, `Assets Logs`, `Digital Risk Keywords Logs`) is fetched separately using its own pagination and limit.

- The integration automatically tracks and stores the last fetched timestamp and event IDs to prevent duplication.

## Configure DeCYFIR Event Collector in Cortex

| **Parameter** | **Required** |
| --- | --- |
| Server URL | True |
| API Key | True |
| Event types to fetch | True |
| Maximum number of Access Logs events per fetch | False |
| Maximum number of Assets Logs events per fetch | False |
| Maximum number of Digital Risk Keywords Logs events per fetch | False |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |

</~XSIAM>
