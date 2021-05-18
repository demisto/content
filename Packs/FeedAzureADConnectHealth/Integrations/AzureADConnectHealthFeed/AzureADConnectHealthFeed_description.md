## Microsoft Azure AD Connect Health web scraper:
https://docs.microsoft.com/en-us/azure/active-directory/hybrid/how-to-connect-health-agent-install#outbound-connectivity-to-the-azure-service-endpoints

NOTE: As we scrape this page, we can not ensure the integrity of the fetched indicators upon a change in the source webpage.

Most IT services are moving from on-premise solutions to cloud-based solutions. The public IP addresses, domains, and URLs that function as the endpoints for these solutions are very often not fixed, and the providers of the service publish their details on their websites in a less than ideal format (i.e.: HTML) rather than through a proper REST API (i.e.: JSON).

This fact makes it very difficult for IT and Security teams to provide these services with an appropriate level of security and automation. Any changes in the HTML schema of the provider website, will break the automation and has the potential to cause serious disruption to the users and the business. The alternative is to compromise on the security posture of the organization.

One example of these providers is Microsoft, and an example of their services is Microsoft Azure AD Connect Health.

The goal of this pack is to address this issue by automating the collection of endpoint data in the form of an indicator feed. This will facilitate validation of the indicators before using them in enforcement points, for example firewalls, proxies, and more.
