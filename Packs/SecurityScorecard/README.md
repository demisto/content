The SecurityScorecard Ratings Content Pack is an integrated offering that provides an alerting system triggered by configurable conditions such as changes in organization grades and vulnerabilities found.

This Content Pack enables security teams to create an alert in SecurityScorecard with particular conditions, which allows them to delete, update and interact with the alerts. A Cortex XSOAR Incident is created when an alert is triggered in SecurityScorecard. Alerts can be retrieved for factor grade drops, overall score drops, new vulnerabilities found, new issues, and CVEs detected.

### What does this pack do?

- Manage (create, delete, list) score or threshold-based alerts.
- Fetches SecurityScorecard alerts into Cortex XSOAR Incidents.
- Retrieves current and historical security scores for organization with the ability to choose specific risk factors such as:
  - **DNS health**: Measurement of DNS configuration presence.
  - **IP Reputation**: Quantity and duration of malware infections.
  - **Web Application Security**: Found web app vulnerabilities such as XSS/SQLi.
  - **Hacker Chatter**: Collection of communications from multiple streams of underground chatter, including hard-to-access or private hacker forums.
  - **Endpoint Security**: Protection involved regarding an organization’s devices that access that company’s network.
  - **Patching Cadence**: How diligently a company is patching its operating systems.
  - **Cubit Score**: Measures a collection of critical security and configuration issues related to exposed administrative portals.

- List portfolios and companies included within those portfolios.
- List companies' 3rd-party services.

The pack includes customized:

- Integration
- Incident Fields
- Incident Type
- Mapper
- Layout
