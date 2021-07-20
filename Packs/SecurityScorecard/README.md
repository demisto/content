# SecurityScorecard

According to Gartner:

>cybersecurity ratings will become as important as credit ratings when assessing the risk of existing and new business relationships…these services will become a precondition for business relationships and part of the standard of due care for providers and procurers of services.

SecurityScorecard is an information security company focused on third party management and IT risk management. It provides a platform designed to rate cybersecurity postures of corporate entities through the scored analysis of cyber threat intelligence signals.

## What does this pack do?

* Manage (create, delete, list) score or threshold-based alerts.
* Creates Cortex XSOAR Incidents based on SecurityScorecard alerts.
* Retrieves current and historical security scores for organization with a the ability to choose specific risk factors explained below:

  * **DNS health**: Measurement of DNS configuration presence.

  * **IP Reputation**: Quantity and duration of malware infections.

  * **Web Application Security**: Found web app vulnerabilities such `XSS/SQLi`.

  * **Hacker Chatter**: Collection of communications from multiple streams of underground chatter, including hard-to-access or private hacker forums.

  * **Endpoint Security**: Protection involved regarding an organization’s devices that access that company’s network.

  * **Patching Cadence**: How diligently a company is patching its operating systems.

  * **Cubit Score**: Measures a collection of critical security and configuration issues related to exposed administrative portals.

* Retrieves list of 3rd party services used by the organization.
* List portfolios and companies included within those portfolios.

The pack includes customized:

* Incident Fields
* Incident Type
* Mapper
* Dashboards
* Layout
* Integration
