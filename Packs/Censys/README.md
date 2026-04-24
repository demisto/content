Note: Support for this Pack was moved to Partner starting April 14, 2026. In case of any issues, please contact the Partner directly at <support@censys.com> or <https://docs.censys.com>.

# Product/Integration Overview

The Censys Platform furnishes real-time intelligence, enabling security teams to reliably detect threats with greater speed, prioritize risks with confidence, and expedite investigations. Through continuous monitoring of the global internet, Censys identifies exposed assets, adversary infrastructure, and security vulnerabilities that conventional tools frequently overlook.

Leveraging industry-leading data accuracy, advanced analytics, and robust search functionalities, Censys mitigates informational clutter, thereby reducing false positives and inefficient effort while simultaneously offering profound visibility into external risks. Security professionals are empowered to track infrastructure modifications, monitor evolving threats, and execute faster, data-driven decisions to safeguard their organizations.

This Integration facilitates the automatic enrichment of data within Palo Alto with information from our Censys Platform, benefiting threat hunters, incident responders, and threat analysts.

## Use Cases

What does this pack do?
The commands in this pack help you retrieve the most accurate and fresh data from Censys Platform helping you navigate Incident Response work faster.
They also help automate repetitive tasks associated with:

1. Retrieve information about the host using its IP address.
2. Retrieve certificate information using its SHA-256 fingerprint.
3. Retrieve web property information using a hostname and port combination.
4. Run a Platform search query.
5. Retrieve the event history for a host.
6. Initiate a live rescan for a known host service at a specific IP and port or a hostname and port.
7. Use the related infrastructure command to discover and map suspicious or malicious internet-facing assets that share parsed Censys data key-value pairs.

To fully leverage the capabilities of this integration, customers need a Censys Adversary Investigation module license, which facilitates the searching of related infrastructure and provides access to the comprehensive dataset.

## Dashboard

- **Censys SOAR Dashboard**: This dashboard displays the total number of times the Censys playbook and Censys commands have been executed, including breakdown by execution type.
