## DomainTools Auto Pivots

This playbook retrieves the Iris Investigate profile of domain and automatically identifies potential connected infrastructure related to artifacts based on DomainTools Guided Pivot value.

## Dependencies

This playbook uses the following sub-playbooks, integrations, lists and scripts.

### Sub-playbooks

This playbook does not use any sub-playbooks.

### Integrations

* DomainTools Iris

### Scripts

Please install this scripts by DomainTools first before running the playbook.

* `CheckPivotableDomains`
* `AddDomainRiskScoreToContext`

### Commands

* domain
* domaintoolsiris-pivot


## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| domains | The domains to lookup.  | None | None | Required |
| dt_riskscore_threshold | The minimum risk score threshold value to check. | 50 | None | Required |
| should_wait_for_analyst_review | Flags if users should wait for an analyst to review. Default is false. Value can be either true/false only. | false | None | Required |
| dt_max_name_server_host_count | The max nameserver host pivot count threshold | 250 | None | No |
| dt_max_registrant_contact_name_count | The max registrant contact name pivot count threshold | 200 | None | No |
| dt_max_registrant_org_count | The max registrant org pivot count threshold  | 200 | None | No |
| dt_max_ssl_info_organization_count | The max ssl info organization pivot count threshold | 200 | None | No |
| dt_max_ssl_info_hash_count | The max ssl info hash pivot count threshold | 350 | None | No |
| dt_max_soa_email_count | The max soa email pivot count threshold | 200 | None | No |
| dt_max_ip_address_count | The max ip address pivot count threshold | 150 | None | No |
| dt_max_name_server_ip_count | The max nameserver ip pivot count threshold | 250 | None | No |
| dt_max_mx_ip_count | The max MX ip pivot count threshold | 200 | None | No |
| dt_max_ssl_email_count | The max ssl email pivot count threshold | 200 | None | No |
| dt_max_registrar_count | The max registrar pivot count threshold | 200 | None | No |
| dt_max_ssl_subject_count | The max ssl subject pivot count threshold | 200 | None | No |
| dt_max_name_server_domain_count | The max name server domain pivot count threshold | 200 | None | No |
| dt_max_mx_host_count | The max MX host pivot count threshold | 200 | None | No |
| dt_max_mx_domain_count | The max MX domain pivot count threshold | 200 | None | No |
| dt_max_google_adsense_count | The max google adsense pivot count threshold | 200 | None | No |
| dt_max_google_analytics_count | The max google analytics pivot count threshold | 200 | None | No |


## Playbook Outputs

---
This playbook extracts results from the 'domaintoolsiris-pivot' command and incorporates them into the context. Furthermore, it identifies high-risk domains by applying a risk score threshold to the pivoted commands.

*Output from `AddDomainRiskScoreToContext`:*
| **Path** | **Description** | **Type** |
| --- | --- | --- |
| HighRiskPivotedDomains.Name | The domain name | String |
| HighRiskPivotedDomains.OverallRiskScore | The overall risk score of the domain | Number |


*Output from `domaintoolsiris-pivot`:*
| **Path** | **Description** | **Type** |
| --- | --- | --- |
| DomainTools.Pivots.PivotedDomains.Name | The DomainTools domain name. | String |
| DomainTools.Pivots.PivotedDomains.LastEnriched | The last time DomainTools enriched domain data. | Date |
| DomainTools.Pivots.PivotedDomains.Analytics.OverallRiskScore | The DomainTools overall risk score. | Number |
| DomainTools.Pivots.PivotedDomains.Analytics.ProximityRiskScore | The DomainTools proximity risk score. | Number |
| DomainTools.Pivots.PivotedDomains.Analytics.ThreatProfileRiskScore.RiskScore | The DomainTools threat profile risk score. | Number |
| DomainTools.Pivots.PivotedDomains.Analytics.ThreatProfileRiskScore.Threats | The DomainTools threat profile threats. | String |
| DomainTools.Pivots.PivotedDomains.Analytics.ThreatProfileRiskScore.Evidence | The DomainTools threat profile evidence. | String |
| DomainTools.Pivots.PivotedDomains.Analytics.WebsiteResponseCode | The website response code. | Number |
| DomainTools.Pivots.PivotedDomains.Analytics.AlexaRank | The Alexa rank. | Number |
| DomainTools.Pivots.PivotedDomains.Analytics.Tags | The DomainTools Tags. | String |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantName | The name of the registrant. | String |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantOrg | The organization of the registrant. | String |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantContact.Country.value | The country value of the registrant contact. | String |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantContact.Country.count | The country count of the registrant contact. | Number |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantContact.Email.value | The email value of the registrant contact. | String |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantContact.Email.count | The email count of the registrant contact. | Number |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantContact.Name.value | The name value of the registrant contact. | String |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantContact.Name.count | The name count of the registrant contact. | Number |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantContact.Phone.value | The phone value of the registrant contact. | String |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantContact.Phone.count | The phone count of the registrant contact. | Number |
| DomainTools.Pivots.PivotedDomains.Identity.SOAEmail | The SOA record Email. | String |
| DomainTools.Pivots.PivotedDomains.Identity.SSLCertificateEmail | The SSL certificate email. | String |
| DomainTools.Pivots.PivotedDomains.Identity.AdminContact.Country.value | The country value of the administrator contact. | String |
| DomainTools.Pivots.PivotedDomains.Identity.AdminContact.Country.count | The country count of the administrator contact. | Number |
| DomainTools.Pivots.PivotedDomains.Identity.AdminContact.Email.value | The email value of the administrator contact. | String |
| DomainTools.Pivots.PivotedDomains.Identity.AdminContact.Email.count | The email count of the administrator contact. | Number |
| DomainTools.Pivots.PivotedDomains.Identity.AdminContact.Name.value | The name value of the administrator contact. | String |
| DomainTools.Pivots.PivotedDomains.Identity.AdminContact.Name.count | The name count of the administrator contact. | Number |
| DomainTools.Pivots.PivotedDomains.Identity.AdminContact.Phone.value | The phone value of the administrator contact. | String |
| DomainTools.Pivots.PivotedDomains.Identity.AdminContact.Phone.count | The phone count of the administrator contact. | Number |
| DomainTools.Pivots.PivotedDomains.Identity.TechnicalContact.Country.value | The country value of the technical contact. | String |
| DomainTools.Pivots.PivotedDomains.Identity.TechnicalContact.Country.count | The country count of the technical contact. | Number |
| DomainTools.Pivots.PivotedDomains.Identity.TechnicalContact.Email.value | The email value of the technical contact. | String |
| DomainTools.Pivots.PivotedDomains.Identity.TechnicalContact.Email.count | The email count of the technical contact. | Number |
| DomainTools.Pivots.PivotedDomains.Identity.TechnicalContact.Name.value | The name value of the technical contact. | String |
| DomainTools.Pivots.PivotedDomains.Identity.TechnicalContact.Name.count | The name count of the technical contact. | Number |
| DomainTools.Pivots.PivotedDomains.Identity.TechnicalContact.Phone.value | The phone value of the technical contact. | String |
| DomainTools.Pivots.PivotedDomains.Identity.TechnicalContact.Phone.count | The phone count of the technical contact. | Number |
| DomainTools.Pivots.PivotedDomains.Identity.BillingContact.Country.value | The country value of the billing contact. | String |
| DomainTools.Pivots.PivotedDomains.Identity.BillingContact.Country.count | The country count of the billing contact. | Number |
| DomainTools.Pivots.PivotedDomains.Identity.BillingContact.Email.value | The email value of the billing contact. | String |
| DomainTools.Pivots.PivotedDomains.Identity.BillingContact.Email.count | The email count of the billing contact. | Number |
| DomainTools.Pivots.PivotedDomains.Identity.BillingContact.Name.value | The name value of the billing contact. | String |
| DomainTools.Pivots.PivotedDomains.Identity.BillingContact.Name.count | The name count of the billing contact. | Number |
| DomainTools.Pivots.PivotedDomains.Identity.BillingContact.Phone.value | The phone value of the billing contact. | String |
| DomainTools.Pivots.PivotedDomains.Identity.BillingContact.Phone.count | The phone count of the billing contact. | Number |
| DomainTools.Pivots.PivotedDomains.Identity.EmailDomains | The email domains. | String |
| DomainTools.Pivots.PivotedDomains.Identity.AdditionalWhoisEmails.value | The value of the additional Whois emails. | String |
| DomainTools.Pivots.PivotedDomains.Identity.AdditionalWhoisEmails.count | The count of the additional Whois emails. | Number |
| DomainTools.Pivots.PivotedDomains.Registration.DomainRegistrant | The registrant of the domain. | String |
| DomainTools.Pivots.PivotedDomains.Registration.RegistrarStatus | The status of the registrar. | String |
| DomainTools.Pivots.PivotedDomains.Registration.DomainStatus | The active status of the domain. | Boolean |
| DomainTools.Pivots.PivotedDomains.Registration.CreateDate | The date the domain was created. | Date |
| DomainTools.Pivots.PivotedDomains.Registration.ExpirationDate | The expiry date of the domain. | Date |
| DomainTools.Pivots.PivotedDomains.Hosting.IPAddresses.address.value | The address value of the IP Addresses. | String |
| DomainTools.Pivots.PivotedDomains.Hosting.IPAddresses.address.count | The address count of the IP Addresses. | Number |
| DomainTools.Pivots.PivotedDomains.Hosting.IPAddresses.asn.value | The ASN value of the IP Addresses. | String |
| DomainTools.Pivots.PivotedDomains.Hosting.IPAddresses.asn.count | The ASN count of the IP Addresses. | Number |
| DomainTools.Pivots.PivotedDomains.Hosting.IPAddresses.country_code.value | The country code value of the IP Addresses. | String |
| DomainTools.Pivots.PivotedDomains.Hosting.IPAddresses.country_code.count | The country code count of the IP Addresses. | Number |
| DomainTools.Pivots.PivotedDomains.Hosting.IPAddresses.isp.value | The ISP value of the IP Addresses. | String |
| DomainTools.Pivots.PivotedDomains.Hosting.IPAddresses.isp.count | The ISP count of the IP Addresses. | Number |
| DomainTools.Pivots.PivotedDomains.Hosting.IPCountryCode | The country code of the IP address. | String |
| DomainTools.Pivots.PivotedDomains.Hosting.MailServers.domain.value | The domain value of the mail servers. | String |
| DomainTools.Pivots.PivotedDomains.Hosting.MailServers.domain.count | The domain count of the mail servers. | Number |
| DomainTools.Pivots.PivotedDomains.Hosting.MailServers.host.value | The host value of the mail servers. | String |
| DomainTools.Pivots.PivotedDomains.Hosting.MailServers.host.count | The host count of the mail servers. | Number |
| DomainTools.Pivots.PivotedDomains.Hosting.MailServers.ip.value | The IP value of the mail servers. | String |
| DomainTools.Pivots.PivotedDomains.Hosting.MailServers.ip.count | The IP count of the mail servers. | Number |
| DomainTools.Pivots.PivotedDomains.Hosting.SPFRecord | The SPF record. | String |
| DomainTools.Pivots.PivotedDomains.Hosting.NameServers.domain.value | The domain value of the DomainTools domains name servers. | String |
| DomainTools.Pivots.PivotedDomains.Hosting.NameServers.domain.count | The domain count of the domainTools Domains name servers. | Number |
| DomainTools.Pivots.PivotedDomains.Hosting.NameServers.host.value | The host value of the DomainTools domains name servers. | String |
| DomainTools.Pivots.PivotedDomains.Hosting.NameServers.host.count | The host count of the DomainTools domains name servers. | Number |
| DomainTools.Pivots.PivotedDomains.Hosting.NameServers.ip.value | The IP value of the DomainTools domains name servers. | String |
| DomainTools.Pivots.PivotedDomains.Hosting.NameServers.ip.count | The IP count of the DomainTools domains name servers. | Number |
| DomainTools.Pivots.PivotedDomains.Hosting.SSLCertificate.hash.value | The hash value of the SSL certificate. | String |
| DomainTools.Pivots.PivotedDomains.Hosting.SSLCertificate.hash.count | The hash count of the SSL certificate. | Number |
| DomainTools.Pivots.PivotedDomains.Hosting.SSLCertificate.organization.value | The organization value of the SSL certificate. | String |
| DomainTools.Pivots.PivotedDomains.Hosting.SSLCertificate.organization.count | The organization count of the SSL certificate. | Number |
| DomainTools.Pivots.PivotedDomains.Hosting.SSLCertificate.subject.value | The subject value of the SSL certificate. | String |
| DomainTools.Pivots.PivotedDomains.Hosting.SSLCertificate.subject.count | The subject count of the SSL certificate. | Number |
| DomainTools.Pivots.PivotedDomains.Hosting.RedirectsTo.value | The redirects to value of the domain. | String |
| DomainTools.Pivots.PivotedDomains.Hosting.RedirectsTo.count | The redirects to count of the domain. | Number |
| DomainTools.Pivots.PivotedDomains.Analytics.GoogleAdsenseTrackingCode | The tracking code of Google Adsense. | Number |
| DomainTools.Pivots.PivotedDomains.Analytics.GoogleAnalyticTrackingCode | The tracking code of Google Analytics. | Number |
