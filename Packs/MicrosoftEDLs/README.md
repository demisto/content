Most IT services are moving from on-premise solutions to cloud-based solutions. The public IP addresses, domains and URL's that function as the endpoints for these solutions, are very often not fixed and the providers of the service publish their details on their websites in an unstructured format (i.e.: HTML) rather than through a proper REST API (i.e.: JSON). 

This fact makes it very difficult for IT and Security teams to provide these services with an appropriate level of security and automation. Any changes in the HTML schema of the provider website, will break the automation and has the potential to cause serious disruption to the users and the business.

One example of these providers is Microsoft, and an example of their services is [Microsoft Intune](https://en.wikipedia.org/wiki/Microsoft_Intune).

The goal of this pack is to address this issue by automating the collection of endpoint data, performing validation and pushing the changes to an EDL that can be consumed automatically by security enforcement technologies (i.e.: NGFW).

The most important element in the provided playbook is the inclusion of a human decision maker in the process. Any changes in the list of endpoints will halt the process until a human analyst reviews the information that is neatly provided and takes the appropriate decision.

## Requirements
Integrations:
- Palo Alto Networks PAN-OS EDL Management
- Palo Alto Networks MineMeld

Scripts:
- GetMSFTIntuneEndpointsList

