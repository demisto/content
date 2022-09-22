The SecurityScorecard Ratings Content Pack is an integrated offering that provides an alerting system triggered by configurable conditions such as changes in organization grades and vulnerabilities found.

This Content Pack enables security teams to create an alert in SecurityScorecard with particular conditions, which allows them to delete, update and interact with the alerts. A Cortex XSOAR Incident is created when an alert is triggered in SecurityScorecard. Alerts can be retrieved for factor grade drops, overall score drops, new vulnerabilities found, new issues, and CVEs detected.

### What does this pack do?

- Manage (create, delete, list) score or threshold-based alerts.
- Fetches SecurityScorecard alerts into Cortex XSOAR Incidents.
- Retrieves current and historical security scores for organization with the ability to choose specific risk factors such as:
  - **Cloud Security**: Measures security of your cloud infrastructure.
  - **Internal Security**: Measures security of your internal networks.
  - **Network Security**: Detecting insecure network settings.
  - **DNS Health**: Detecting DNS insecure configurations and vulnerabilities.
  - **Patching Cadence**: Out of date company assets which may contain vulnerabilities or risks.
  - **Endpoint Security**: Detecting unprotected endpoints or entry points of user tools, such as desktops, laptops, mobile devices, and virtual desktops.
  - **IP Reputation**: Detecting suspicious activity, such as malware or spam, within your company network.
  - **Application Security**: Detecting common website application vulnerabilities.
  - **Cubit Score**: Proprietary algorithms checking for implementation of common security best practices.
  - **Hacker Chatter**: Monitoring hacker sites for chatter about your company.
  - **Information Leak**: Potentially confidential company information which may have been inadvertently leaked.
  - **Social Engineering**: Measuring company awareness to a social engineering or phishing attack.

- List portfolios and companies included within those portfolios.
- List companies' 3rd-party services.

The pack includes customized:

- Integration
- Incident Fields
- Incident Type
- Mapper
- Layout
