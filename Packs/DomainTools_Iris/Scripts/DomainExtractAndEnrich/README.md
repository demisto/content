Resolves a URL or fully qualified domain name (FQDN) and looks up a complete profile of the domain on the DomainTools Iris Enrich API.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | DomainTools |
| Cortex XSOAR Version | 6.9.0 |

## Dependencies

---
This script uses the following commands and scripts.

* domaintoolsiris-enrich
* DomainTools Iris
* ExtractDomainFromUrlAndEmail

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| url | Resolve and enrich domains from this URL. Also accepts a comma-separated list of up to 6,000 URLs. |
| include_context | Optionally include the investigate results into the Context Data. Defaults to false. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Domain.Name | The name of the domain. | String |
| Domain.DNS | The DNS of the domain. | String |
| Domain.DomainStatus | The status of the domain. | Boolean |
| Domain.CreationDate | The creation date. | Date |
| Domain.ExpirationDate | The expiration date of the domain. | Date |
| Domain.NameServers | The nameServers of the domain. | String |
| Domain.Registrant.Country | The registrant country of the domain. | String |
| Domain.Registrant.Email | The registrant email of the domain. | String |
| Domain.Registrant.Name | The registrant name of the domain. | String |
| Domain.Registrant.Phone | The registrant phone number of the domain. | String |
| Domain.Malicious.Vendor | The vendor who classified the domain as malicious. | String |
| Domain.Malicious.Description | The description as to why the domain was found to be malicious. | String |
| DomainTools.Domains.Name | The domain name in DomainTools. | String |
| DomainTools.Domains.LastEnriched | The last Time DomainTools enriched domain data. | Date |
| DomainTools.Domains.Analytics.OverallRiskScore | The Overall Risk Score in DomainTools. | Number |
| DomainTools.Domains.Analytics.ProximityRiskScore | The Proximity Risk Score in DomainTools. | Number |
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.RiskScore | The Threat Profile Risk Score in DomainTools. | Number |
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Threats | The threats of the Threat Profile Risk Score in DomainTools. | String |
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Evidence | The Threat Profile Risk Score Evidence in DomainTools. | String |
| DomainTools.Domains.Analytics.WebsiteResponseCode | The Website Response Code in DomainTools. | Number |
| DomainTools.Domains.Analytics.AlexaRank | The Alexa Rank in DomainTools. | Number |
| DomainTools.Domains.Analytics.Tags | The Tags in DomainTools. | String |
| DomainTools.Domains.Identity.RegistrantName | The name of the registrant. | String |
| DomainTools.Domains.Identity.RegistrantOrg | The organization of the registrant. | String |
| DomainTools.Domains.Identity.RegistrantContact.Country.value | The country value of the registrant contact. | String |
| DomainTools.Domains.Identity.RegistrantContact.Country.count | The count of the registrant contact country. | Number |
| DomainTools.Domains.Identity.RegistrantContact.Email.value | The Email value of the registrant contact. | String |
| DomainTools.Domains.Identity.RegistrantContact.Email.count | The Email count of the registrant contact. | Number |
| DomainTools.Domains.Identity.RegistrantContact.Name.value | The name value of the registrant contact. | String |
| DomainTools.Domains.Identity.RegistrantContact.Name.count | The name count of the registrant contact. | Number |
| DomainTools.Domains.Identity.RegistrantContact.Phone.value | The phone value of the registrant contact. | String |
| DomainTools.Domains.Identity.RegistrantContact.Phone.count | The phone count of the registrant contact. | Number |
| DomainTools.Domains.Identity.SOAEmail | The SOA record of the Email. | String |
| DomainTools.Domains.Identity.SSLCertificateEmail | The Email of the SSL certificate. | String |
| DomainTools.Domains.Identity.AdminContact.Country.value | The country value of the administrator contact. | String |
| DomainTools.Domains.Identity.AdminContact.Country.count | The country count of the administrator contact. | Number |
| DomainTools.Domains.Identity.AdminContact.Email.value | The Email value of the administrator contact. | String |
| DomainTools.Domains.Identity.AdminContact.Email.count | The Email count of the administrator contact. | Number |
| DomainTools.Domains.Identity.AdminContact.Name.value | The name value of the administrator contact. | String |
| DomainTools.Domains.Identity.AdminContact.Name.count | The name count of the administrator contact. | Number |
| DomainTools.Domains.Identity.AdminContact.Phone.value | The phone value of the administrator contact. | String |
| DomainTools.Domains.Identity.AdminContact.Phone.count | The phone count of the administrator contact. | Number |
| DomainTools.Domains.Identity.TechnicalContact.Country.value | The country value of the technical contact. | String |
| DomainTools.Domains.Identity.TechnicalContact.Country.count | The country count of the technical contact. | Number |
| DomainTools.Domains.Identity.TechnicalContact.Email.value | The Email value of the technical contact. | String |
| DomainTools.Domains.Identity.TechnicalContact.Email.count | The Email count of the technical contact. | Number |
| DomainTools.Domains.Identity.TechnicalContact.Name.value | The name value of the technical Contact. | String |
| DomainTools.Domains.Identity.TechnicalContact.Name.count | The name count of the technical contact. | Number |
| DomainTools.Domains.Identity.TechnicalContact.Phone.value | The phone value of the technical contact. | String |
| DomainTools.Domains.Identity.TechnicalContact.Phone.count | The phone count of the technical contact. | Number |
| DomainTools.Domains.Identity.BillingContact.Country.value | The country value of the billing contact. | String |
| DomainTools.Domains.Identity.BillingContact.Country.count | The country count of the billing contact. | Number |
| DomainTools.Domains.Identity.BillingContact.Email.value | The Email value of the billing contact. | String |
| DomainTools.Domains.Identity.BillingContact.Email.count | The Email count of the billing contact. | Number |
| DomainTools.Domains.Identity.BillingContact.Name.value | The name value of the billing contact. | String |
| DomainTools.Domains.Identity.BillingContact.Name.count | The name count of the billing contact. | Number |
| DomainTools.Domains.Identity.BillingContact.Phone.value | The phone value of the billing contact. | String |
| DomainTools.Domains.Identity.BillingContact.Phone.count | The phone count of the billing contact. | Number |
| DomainTools.Domains.Identity.EmailDomains | The Email Domains. | String |
| DomainTools.Domains.Identity.AdditionalWhoisEmails.value | The value of the Additional Whois Emails record. | String |
| DomainTools.Domains.Identity.AdditionalWhoisEmails.count | The count of the Additional Whois Emails record. | Number |
| DomainTools.Domains.Registration.DomainRegistrant | The registrant of the domain. | String |
| DomainTools.Domains.Registration.RegistrarStatus | The status of the registrar. | String |
| DomainTools.Domains.Registration.DomainStatus | The active status of the domain. | Boolean |
| DomainTools.Domains.Registration.CreateDate | The date the domain was created. | Date |
| DomainTools.Domains.Registration.ExpirationDate | The expiration date of the domain. | Date |
| DomainTools.Domains.Hosting.IPAddresses.address.value | The address value of IP addresses. | String |
| DomainTools.Domains.Hosting.IPAddresses.address.count | The address count of IP addresses. | Number |
| DomainTools.Domains.Hosting.IPAddresses.asn.value | The ASN value of IP addresses. | String |
| DomainTools.Domains.Hosting.IPAddresses.asn.count | The ASN count of IP addresses. | Number |
| DomainTools.Domains.Hosting.IPAddresses.country_code.value | The country code value of IP addresses. | String |
| DomainTools.Domains.Hosting.IPAddresses.country_code.count | The country code count of IP addresses. | Number |
| DomainTools.Domains.Hosting.IPAddresses.isp.value | The ISP value of IP addresses. | String |
| DomainTools.Domains.Hosting.IPAddresses.isp.count | The ISP count of IP addresses. | Number |
| DomainTools.Domains.Hosting.IPCountryCode | The country code of the IP address. | String |
| DomainTools.Domains.Hosting.MailServers.domain.value | The domain value of the Mail Servers. | String |
| DomainTools.Domains.Hosting.MailServers.domain.count | The domain count of the Mail Servers. | Number |
| DomainTools.Domains.Hosting.MailServers.host.value | The host value of the Mail Servers. | String |
| DomainTools.Domains.Hosting.MailServers.host.count | The host count of the Mail Servers. | Number |
| DomainTools.Domains.Hosting.MailServers.ip.value | The IP value of the Mail Servers. | String |
| DomainTools.Domains.Hosting.MailServers.ip.count | The IP count of the Mail Servers. | Number |
| DomainTools.Domains.Hosting.SPFRecord | The SPF Record. | String |
| DomainTools.Domains.Hosting.NameServers.domain.value | The domain value of the domain NameServers. | String |
| DomainTools.Domains.Hosting.NameServers.domain.count | The domain count of the domain NameServers. | Number |
| DomainTools.Domains.Hosting.NameServers.host.value | The host value of the domain NameServers. | String |
| DomainTools.Domains.Hosting.NameServers.host.count | The host count of the domain NameServers. | Number |
| DomainTools.Domains.Hosting.NameServers.ip.value | The IP value of the domain NameServers. | String |
| DomainTools.Domains.Hosting.NameServers.ip.count | The IP count of domain NameServers. | Number |
| DomainTools.Domains.Hosting.SSLCertificate.hash.value | The hash value of the SSL certificate. | String |
| DomainTools.Domains.Hosting.SSLCertificate.hash.count | The hash count of the SSL certificate. | Number |
| DomainTools.Domains.Hosting.SSLCertificate.organization.value | The organization value of the SSL certificate. | String |
| DomainTools.Domains.Hosting.SSLCertificate.organization.count | The organization count of the SSL certificate information. | Number |
| DomainTools.Domains.Hosting.SSLCertificate.subject.value | The subject value of the SSL certificate information. | String |
| DomainTools.Domains.Hosting.SSLCertificate.subject.count | The subject count of the SSL certificate information. | Number |
| DomainTools.Domains.Hosting.RedirectsTo.value | The Redirects To Value of the domain. | String |
| DomainTools.Domains.Hosting.RedirectsTo.count | The Redirects To Count of the domain. | Number |
| DomainTools.Domains.Analytics.GoogleAdsenseTrackingCode | The tracking code of Google Adsense. | Number |
| DomainTools.Domains.Analytics.GoogleAnalyticTrackingCode | The tracking code of Google Analytics. | Number |
| DBotScore.Indicator | The indicator of the DBotScore. | String |
| DBotScore.Type | The indicator type of the DBotScore. | String |
| DBotScore.Vendor | The vendor used to calculate the score. | String |
| DBotScore.Score | The actual score. | Number |
