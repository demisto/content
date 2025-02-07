Together, DomainTools and Cortex XSOAR automate and orchestrate the incident response process with essential domain profile, web crawl, SSL and infrastructure data. SOCs can create custom, automated workflows to trigger Indicator of Compromise (IoC) investigations, block threats based on connected infrastructure, and identify potentially malicious domains before weaponization. The DomainTools App for Cortex XSOAR is shipped with pre-built playbooks to enable automated enrichment, decision logic, ad-hoc investigations, and the ability to persist enriched intelligence.
This integration was integrated and tested with version 2.1.3 of DomainTools Iris.

## Configure DomainTools Iris in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| DomainTools API URL | Change to <https://api.domaintools.com> in order to use DomainTool's https endpoint. | True |
| API Username |  | True |
| API Key |  | True |
| High-Risk Threshold |  | True |
| Young Domain Timeframe (within Days) |  | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |
|  |  | False |
|  |  | False |
| Guided Pivot Threshold | When a small set of domains share an attribute \(e.g. registrar\), that can often be pivoted on in order to find other similar domains of interest. DomainTools tracks how many domains share each attribute and can highlight it for further investigation when the number of domains is beneath the set threshold. | True |
| Enabled on Monitoring Domains by Iris Search Hash |  | False |
| Domaintools Iris Investigate Search Hash | The DomainTools Iris Investigate Search hash | False |
| Enabled on Monitoring Domains by Iris Tags |  | False |
| Domaintools Iris Tags | The DomainTools Iris Tags \(Values should be a comma separated value. e.g. \(tag1,tag2\)\) | False |
| Maximum number of incidents to fetch | This is a required field by XSOAR and should be set to 2, one for each possible feed type iris search hash and iris tags. | False |
| Incident type |  |  |
| Fetch incidents |  |  |
| First fetch timestamp (&lt;number&gt; &lt;time unit&gt;, e.g., 12 hours, 7 days) | This is a required field by XSOAR and should be set to 2, one for each possible feed type iris search hash and iris tags. | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### domain

***
Provides data enrichment for domains.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain to enrich. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The name of the domain. |
| Domain.DNS | String | The DNS of the domain. |
| Domain.DomainStatus | Boolean | The status of the domain. |
| Domain.CreationDate | Date | The creation date. |
| Domain.ExpirationDate | Date | The expiration date of the domain. |
| Domain.NameServers | String | The nameServers of the domain. |
| Domain.Registrant.Country | String | The registrant country of the domain. |
| Domain.Registrant.Email | String | The registrant email of the domain. |
| Domain.Registrant.Name | String | The registrant name of the domain. |
| Domain.Registrant.Phone | String | The registrant phone number of the domain. |
| Domain.Malicious.Vendor | String | The vendor who classified the domain as malicious. |
| Domain.Malicious.Description | String | The description as to why the domain was found to be malicious. |
| DomainTools.Name | String | The domain name in DomainTools. |
| DomainTools.LastEnriched | Date | The last Time DomainTools enriched domain data. |
| DomainTools.Analytics.OverallRiskScore | Number | The Overall Risk Score in DomainTools. |
| DomainTools.Analytics.ProximityRiskScore | Number | The Proximity Risk Score in DomainTools. |
| DomainTools.Analytics.ThreatProfileRiskScore.RiskScore | Number | The Threat Profile Risk Score in DomainTools. |
| DomainTools.Analytics.ThreatProfileRiskScore.Threats | String | The threats of the Threat Profile Risk Score in DomainTools. |
| DomainTools.Analytics.ThreatProfileRiskScore.Evidence | String | The Threat Profile Risk Score Evidence in DomainTools. |
| DomainTools.Analytics.WebsiteResponseCode | Number | The Website Response Code in DomainTools. |
| DomainTools.Analytics.Tags | String | The Tags in DomainTools. |
| DomainTools.Identity.RegistrantName | String | The name of the registrant. |
| DomainTools.Identity.RegistrantOrg | String | The organization of the registrant. |
| DomainTools.Identity.RegistrantContact.Country.value | String | The country value of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Country.count | Number | The count of the registrant contact country. |
| DomainTools.Identity.RegistrantContact.Email.value | String | The Email value of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Email.count | Number | The Email count of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Name.value | String | The name value of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Name.count | Number | The name count of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Phone.value | String | The phone value of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Phone.count | Number | The phone count of the registrant contact. |
| DomainTools.Identity.SOAEmail | String | The SOA record of the Email. |
| DomainTools.Identity.SSLCertificateEmail | String | The Email of the SSL certificate. |
| DomainTools.Identity.AdminContact.Country.value | String | The country value of the administrator contact. |
| DomainTools.Identity.AdminContact.Country.count | Number | The country count of the administrator contact. |
| DomainTools.Identity.AdminContact.Email.value | String | The Email value of the administrator contact. |
| DomainTools.Identity.AdminContact.Email.count | Number | The Email count of the administrator contact. |
| DomainTools.Identity.AdminContact.Name.value | String | The name value of the administrator contact. |
| DomainTools.Identity.AdminContact.Name.count | Number | The name count of the administrator contact. |
| DomainTools.Identity.AdminContact.Phone.value | String | The phone value of the administrator contact. |
| DomainTools.Identity.AdminContact.Phone.count | Number | The phone count of the administrator contact. |
| DomainTools.Identity.TechnicalContact.Country.value | String | The country value of the technical contact. |
| DomainTools.Identity.TechnicalContact.Country.count | Number | The country count of the technical contact. |
| DomainTools.Identity.TechnicalContact.Email.value | String | The Email value of the technical contact. |
| DomainTools.Identity.TechnicalContact.Email.count | Number | The Email count of the technical contact. |
| DomainTools.Identity.TechnicalContact.Name.value | String | The name value of the technical Contact. |
| DomainTools.Identity.TechnicalContact.Name.count | Number | The name count of the technical contact. |
| DomainTools.Identity.TechnicalContact.Phone.value | String | The phone value of the technical contact. |
| DomainTools.Identity.TechnicalContact.Phone.count | Number | The phone count of the technical contact. |
| DomainTools.Identity.BillingContact.Country.value | String | The country value of the billing contact. |
| DomainTools.Identity.BillingContact.Country.count | Number | The country count of the billing contact. |
| DomainTools.Identity.BillingContact.Email.value | String | The Email value of the billing contact. |
| DomainTools.Identity.BillingContact.Email.count | Number | The Email count of the billing contact. |
| DomainTools.Identity.BillingContact.Name.value | String | The name value of the billing contact. |
| DomainTools.Identity.BillingContact.Name.count | Number | The name count of the billing contact. |
| DomainTools.Identity.BillingContact.Phone.value | String | The phone value of the billing contact. |
| DomainTools.Identity.BillingContact.Phone.count | Number | The phone count of the billing contact. |
| DomainTools.Identity.EmailDomains | String | The Email Domains. |
| DomainTools.Identity.AdditionalWhoisEmails.value | String | The value of the Additional Whois Emails record. |
| DomainTools.Identity.AdditionalWhoisEmails.count | Number | The count of the Additional Whois Emails record. |
| DomainTools.Registration.DomainRegistrant | String | The registrant of the domain. |
| DomainTools.Registration.RegistrarStatus | String | The status of the registrar. |
| DomainTools.Registration.DomainStatus | Boolean | The active status of the domain. |
| DomainTools.Registration.CreateDate | Date | The date the domain was created. |
| DomainTools.Registration.ExpirationDate | Date | The expiration date of the domain. |
| DomainTools.Hosting.IPAddresses.address.value | String | The address value of IP addresses. |
| DomainTools.Hosting.IPAddresses.address.count | Number | The address count of IP addresses. |
| DomainTools.Hosting.IPAddresses.asn.value | String | The ASN value of IP addresses. |
| DomainTools.Hosting.IPAddresses.asn.count | Number | The ASN count of IP addresses. |
| DomainTools.Hosting.IPAddresses.country_code.value | String | The country code value of IP addresses. |
| DomainTools.Hosting.IPAddresses.country_code.count | Number | The country code count of IP addresses. |
| DomainTools.Hosting.IPAddresses.isp.value | String | The ISP value of IP addresses. |
| DomainTools.Hosting.IPAddresses.isp.count | Number | The ISP count of IP addresses. |
| DomainTools.Hosting.IPCountryCode | String | The country code of the IP address. |
| DomainTools.Hosting.MailServers.domain.value | String | The domain value of the Mail Servers. |
| DomainTools.Hosting.MailServers.domain.count | Number | The domain count of the Mail Servers. |
| DomainTools.Hosting.MailServers.host.value | String | The host value of the Mail Servers. |
| DomainTools.Hosting.MailServers.host.count | Number | The host count of the Mail Servers. |
| DomainTools.Hosting.MailServers.ip.value | String | The IP value of the Mail Servers. |
| DomainTools.Hosting.MailServers.ip.count | Number | The IP count of the Mail Servers. |
| DomainTools.Hosting.SPFRecord | String | The SPF Record. |
| DomainTools.Hosting.NameServers.domain.value | String | The domain value of the domain NameServers. |
| DomainTools.Hosting.NameServers.domain.count | Number | The domain count of the domain NameServers. |
| DomainTools.Hosting.NameServers.host.value | String | The host value of the domain NameServers. |
| DomainTools.Hosting.NameServers.host.count | Number | The host count of the domain NameServers. |
| DomainTools.Hosting.NameServers.ip.value | String | The IP value of the domain NameServers. |
| DomainTools.Hosting.NameServers.ip.count | Number | The IP count of domain NameServers. |
| DomainTools.Hosting.SSLCertificate.hash.value | String | The hash value of the SSL certificate. |
| DomainTools.Hosting.SSLCertificate.hash.count | Number | The hash count of the SSL certificate. |
| DomainTools.Hosting.SSLCertificate.organization.value | String | The organization value of the SSL certificate. |
| DomainTools.Hosting.SSLCertificate.organization.count | Number | The organization count of the SSL certificate information. |
| DomainTools.Hosting.SSLCertificate.subject.value | String | The subject value of the SSL certificate information. |
| DomainTools.Hosting.SSLCertificate.subject.count | Number | The subject count of the SSL certificate information. |
| DomainTools.Hosting.RedirectsTo.value | String | The Redirects To Value of the domain. |
| DomainTools.Hosting.RedirectsTo.count | Number | The Redirects To Count of the domain. |
| DomainTools.Analytics.GoogleAdsenseTrackingCode | Number | The tracking code of Google Adsense. |
| DomainTools.Analytics.GoogleAnalyticTrackingCode | Number | The tracking code of Google Analytics. |
| DomainTools.Domains.Analytics.GA4TrackingCode | Number | The tracking code of ga4. |
| DomainTools.Domains.Analytics.GTMTrackingCode | Number | The tracking code of gtm. |
| DomainTools.Domains.Analytics.FBTrackingCode | Number | The tracking code of fb. |
| DomainTools.Domains.Analytics.HotJarTrackingCode | Number | The tracking code of Hot Jar. |
| DomainTools.Domains.Analytics.BaiduTrackingCode | Number | The tracking code of Baidu. |
| DomainTools.Domains.Analytics.YandexTrackingCode | Number | The tracking code of Yandex. |
| DomainTools.Domains.Analytics.MatomoTrackingCode | Number | The tracking code of Matomo. |
| DomainTools.Domains.Analytics.StatcounterProjectTrackingCode | Number | The tracking code of Stat Counter Project. |
| DomainTools.Domains.Analytics.StatcounterSecurityTrackingCode | Number | The tracking code of Stat Counter Security. |
| DomainTools.WebsiteTitle | Number | The website title. |
| DomainTools.FirstSeen | Number | The date the domain was first seen. |
| DomainTools.ServerType | Number | The server type. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type of the DBotScore. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |

### domaintoolsiris-investigate

***
Returns a complete profile of the domain (SLD.TLD) using Iris Investigate. If parsing of FQDNs is desired, see domainExtractAndInvestigate.

#### Base Command

`domaintoolsiris-investigate`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name (SLD.TLD) to Investigate. Supports up to 1,000 comma-separated domains. | Required |
| include_context | Include the investigate results in Context Data. Defaults to true. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The name of the domain. |
| Domain.DNS | String | The DNS of the domain. |
| Domain.DomainStatus | Boolean | The status of the domain. |
| Domain.CreationDate | Date | The creation date. |
| Domain.ExpirationDate | Date | The expiration date of the domain. |
| Domain.NameServers | String | The nameServers of the domain. |
| Domain.Registrant.Country | String | The registrant country of the domain. |
| Domain.Registrant.Email | String | The registrant email of the domain. |
| Domain.Registrant.Name | String | The registrant name of the domain. |
| Domain.Registrant.Phone | String | The registrant phone number of the domain. |
| Domain.Malicious.Vendor | String | The vendor who classified the domain as malicious. |
| Domain.Malicious.Description | String | The description as to why the domain was found to be malicious. |
| DomainTools.Name | String | The domain name in DomainTools. |
| DomainTools.LastEnriched | Date | The last Time DomainTools enriched domain data. |
| DomainTools.Analytics.OverallRiskScore | Number | The Overall Risk Score in DomainTools. |
| DomainTools.Analytics.ProximityRiskScore | Number | The Proximity Risk Score in DomainTools. |
| DomainTools.Analytics.ThreatProfileRiskScore.RiskScore | Number | The Threat Profile Risk Score in DomainTools. |
| DomainTools.Analytics.ThreatProfileRiskScore.Threats | String | The threats of the Threat Profile Risk Score in DomainTools. |
| DomainTools.Analytics.ThreatProfileRiskScore.Evidence | String | The Threat Profile Risk Score Evidence in DomainTools. |
| DomainTools.Analytics.WebsiteResponseCode | Number | The Website Response Code in DomainTools. |
| DomainTools.Analytics.Tags | String | The Tags in DomainTools. |
| DomainTools.Identity.RegistrantName | String | The name of the registrant. |
| DomainTools.Identity.RegistrantOrg | String | The organization of the registrant. |
| DomainTools.Identity.RegistrantContact.Country.value | String | The country value of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Country.count | Number | The count of the registrant contact country. |
| DomainTools.Identity.RegistrantContact.Email.value | String | The Email value of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Email.count | Number | The Email count of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Name.value | String | The name value of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Name.count | Number | The name count of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Phone.value | String | The phone value of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Phone.count | Number | The phone count of the registrant contact. |
| DomainTools.Identity.SOAEmail | String | The SOA record of the Email. |
| DomainTools.Identity.SSLCertificateEmail | String | The Email of the SSL certificate. |
| DomainTools.Identity.AdminContact.Country.value | String | The country value of the administrator contact. |
| DomainTools.Identity.AdminContact.Country.count | Number | The country count of the administrator contact. |
| DomainTools.Identity.AdminContact.Email.value | String | The Email value of the administrator contact. |
| DomainTools.Identity.AdminContact.Email.count | Number | The Email count of the administrator contact. |
| DomainTools.Identity.AdminContact.Name.value | String | The name value of the administrator contact. |
| DomainTools.Identity.AdminContact.Name.count | Number | The name count of the administrator contact. |
| DomainTools.Identity.AdminContact.Phone.value | String | The phone value of the administrator contact. |
| DomainTools.Identity.AdminContact.Phone.count | Number | The phone count of the administrator contact. |
| DomainTools.Identity.TechnicalContact.Country.value | String | The country value of the technical contact. |
| DomainTools.Identity.TechnicalContact.Country.count | Number | The country count of the technical contact. |
| DomainTools.Identity.TechnicalContact.Email.value | String | The Email value of the technical contact. |
| DomainTools.Identity.TechnicalContact.Email.count | Number | The Email count of the technical contact. |
| DomainTools.Identity.TechnicalContact.Name.value | String | The name value of the technical Contact. |
| DomainTools.Identity.TechnicalContact.Name.count | Number | The name count of the technical contact. |
| DomainTools.Identity.TechnicalContact.Phone.value | String | The phone value of the technical contact. |
| DomainTools.Identity.TechnicalContact.Phone.count | Number | The phone count of the technical contact. |
| DomainTools.Identity.BillingContact.Country.value | String | The country value of the billing contact. |
| DomainTools.Identity.BillingContact.Country.count | Number | The country count of the billing contact. |
| DomainTools.Identity.BillingContact.Email.value | String | The Email value of the billing contact. |
| DomainTools.Identity.BillingContact.Email.count | Number | The Email count of the billing contact. |
| DomainTools.Identity.BillingContact.Name.value | String | The name value of the billing contact. |
| DomainTools.Identity.BillingContact.Name.count | Number | The name count of the billing contact. |
| DomainTools.Identity.BillingContact.Phone.value | String | The phone value of the billing contact. |
| DomainTools.Identity.BillingContact.Phone.count | Number | The phone count of the billing contact. |
| DomainTools.Identity.EmailDomains | String | The Email Domains. |
| DomainTools.Identity.AdditionalWhoisEmails.value | String | The value of the Additional Whois Emails record. |
| DomainTools.Identity.AdditionalWhoisEmails.count | Number | The count of the Additional Whois Emails record. |
| DomainTools.Registration.DomainRegistrant | String | The registrant of the domain. |
| DomainTools.Registration.RegistrarStatus | String | The status of the registrar. |
| DomainTools.Registration.DomainStatus | Boolean | The active status of the domain. |
| DomainTools.Registration.CreateDate | Date | The date the domain was created. |
| DomainTools.Registration.ExpirationDate | Date | The expiration date of the domain. |
| DomainTools.Hosting.IPAddresses.address.value | String | The address value of IP addresses. |
| DomainTools.Hosting.IPAddresses.address.count | Number | The address count of IP addresses. |
| DomainTools.Hosting.IPAddresses.asn.value | String | The ASN value of IP addresses. |
| DomainTools.Hosting.IPAddresses.asn.count | Number | The ASN count of IP addresses. |
| DomainTools.Hosting.IPAddresses.country_code.value | String | The country code value of IP addresses. |
| DomainTools.Hosting.IPAddresses.country_code.count | Number | The country code count of IP addresses. |
| DomainTools.Hosting.IPAddresses.isp.value | String | The ISP value of IP addresses. |
| DomainTools.Hosting.IPAddresses.isp.count | Number | The ISP count of IP addresses. |
| DomainTools.Hosting.IPCountryCode | String | The country code of the IP address. |
| DomainTools.Hosting.MailServers.domain.value | String | The domain value of the Mail Servers. |
| DomainTools.Hosting.MailServers.domain.count | Number | The domain count of the Mail Servers. |
| DomainTools.Hosting.MailServers.host.value | String | The host value of the Mail Servers. |
| DomainTools.Hosting.MailServers.host.count | Number | The host count of the Mail Servers. |
| DomainTools.Hosting.MailServers.ip.value | String | The IP value of the Mail Servers. |
| DomainTools.Hosting.MailServers.ip.count | Number | The IP count of the Mail Servers. |
| DomainTools.Hosting.SPFRecord | String | The SPF Record. |
| DomainTools.Hosting.NameServers.domain.value | String | The domain value of the domain NameServers. |
| DomainTools.Hosting.NameServers.domain.count | Number | The domain count of the domain NameServers. |
| DomainTools.Hosting.NameServers.host.value | String | The host value of the domain NameServers. |
| DomainTools.Hosting.NameServers.host.count | Number | The host count of the domain NameServers. |
| DomainTools.Hosting.NameServers.ip.value | String | The IP value of the domain NameServers. |
| DomainTools.Hosting.NameServers.ip.count | Number | The IP count of domain NameServers. |
| DomainTools.Hosting.SSLCertificate.hash.value | String | The hash value of the SSL certificate. |
| DomainTools.Hosting.SSLCertificate.hash.count | Number | The hash count of the SSL certificate. |
| DomainTools.Hosting.SSLCertificate.organization.value | String | The organization value of the SSL certificate. |
| DomainTools.Hosting.SSLCertificate.organization.count | Number | The organization count of the SSL certificate information. |
| DomainTools.Hosting.SSLCertificate.subject.value | String | The subject value of the SSL certificate information. |
| DomainTools.Hosting.SSLCertificate.subject.count | Number | The subject count of the SSL certificate information. |
| DomainTools.Hosting.RedirectsTo.value | String | The Redirects To Value of the domain. |
| DomainTools.Hosting.RedirectsTo.count | Number | The Redirects To Count of the domain. |
| DomainTools.Analytics.GoogleAdsenseTrackingCode | Number | The tracking code of Google Adsense. |
| DomainTools.Analytics.GoogleAnalyticTrackingCode | Number | The tracking code of Google Analytics. |
| DomainTools.Domains.Analytics.GA4TrackingCode | Number | The tracking code of ga4. |
| DomainTools.Domains.Analytics.GTMTrackingCode | Number | The tracking code of gtm. |
| DomainTools.Domains.Analytics.FBTrackingCode | Number | The tracking code of fb. |
| DomainTools.Domains.Analytics.HotJarTrackingCode | Number | The tracking code of Hot Jar. |
| DomainTools.Domains.Analytics.BaiduTrackingCode | Number | The tracking code of Baidu. |
| DomainTools.Domains.Analytics.YandexTrackingCode | Number | The tracking code of Yandex. |
| DomainTools.Domains.Analytics.MatomoTrackingCode | Number | The tracking code of Matomo. |
| DomainTools.Domains.Analytics.StatcounterProjectTrackingCode | Number | The tracking code of Stat Counter Project. |
| DomainTools.Domains.Analytics.StatcounterSecurityTrackingCode | Number | The tracking code of Stat Counter Security. |
| DomainTools.WebsiteTitle | Number | The website title. |
| DomainTools.FirstSeen | Number | The date the domain was first seen. |
| DomainTools.ServerType | Number | The server type. |
| DBotScore.Indicator | String | The indicator of the DBotScore. |
| DBotScore.Type | String | The indicator type of the DBotScore. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |

### domaintoolsiris-enrich

***
Returns a complete profile of the domain (SLD.TLD) using Iris Enrich. If parsing of URLs or FQDNs is desired, see domainExtractAndEnrich.

#### Base Command

`domaintoolsiris-enrich`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name (SLD.TLD), or a comma-separated list of up to 6,000 domains. | Required |
| include_context | Include the investigate results in Context Data. Defaults to true. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The name of the domain. |
| Domain.DNS | String | The DNS of the domain. |
| Domain.DomainStatus | Boolean | The status of the domain. |
| Domain.CreationDate | Date | The creation date. |
| Domain.ExpirationDate | Date | The expiration date of the domain. |
| Domain.NameServers | String | The nameServers of the domain. |
| Domain.Registrant.Country | String | The registrant country of the domain. |
| Domain.Registrant.Email | String | The registrant email of the domain. |
| Domain.Registrant.Name | String | The registrant name of the domain. |
| Domain.Registrant.Phone | String | The registrant phone number of the domain. |
| Domain.Malicious.Vendor | String | The vendor who classified the domain as malicious. |
| Domain.Malicious.Description | String | The description as to why the domain was found to be malicious. |
| DomainTools.Name | String | The domain name in DomainTools. |
| DomainTools.LastEnriched | Date | The last Time DomainTools enriched domain data. |
| DomainTools.Analytics.OverallRiskScore | Number | The Overall Risk Score in DomainTools. |
| DomainTools.Analytics.ProximityRiskScore | Number | The Proximity Risk Score in DomainTools. |
| DomainTools.Analytics.ThreatProfileRiskScore.RiskScore | Number | The Threat Profile Risk Score in DomainTools. |
| DomainTools.Analytics.ThreatProfileRiskScore.Threats | String | The threats of the Threat Profile Risk Score in DomainTools. |
| DomainTools.Analytics.ThreatProfileRiskScore.Evidence | String | The Threat Profile Risk Score Evidence in DomainTools. |
| DomainTools.Analytics.WebsiteResponseCode | Number | The Website Response Code in DomainTools. |
| DomainTools.Analytics.Tags | String | The Tags in DomainTools. |
| DomainTools.Identity.RegistrantName | String | The name of the registrant. |
| DomainTools.Identity.RegistrantOrg | String | The organization of the registrant. |
| DomainTools.Identity.RegistrantContact.Country.value | String | The country value of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Country.count | Number | The count of the registrant contact country. |
| DomainTools.Identity.RegistrantContact.Email.value | String | The Email value of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Email.count | Number | The Email count of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Name.value | String | The name value of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Name.count | Number | The name count of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Phone.value | String | The phone value of the registrant contact. |
| DomainTools.Identity.RegistrantContact.Phone.count | Number | The phone count of the registrant contact. |
| DomainTools.Identity.SOAEmail | String | The SOA record of the Email. |
| DomainTools.Identity.SSLCertificateEmail | String | The Email of the SSL certificate. |
| DomainTools.Identity.AdminContact.Country.value | String | The country value of the administrator contact. |
| DomainTools.Identity.AdminContact.Country.count | Number | The country count of the administrator contact. |
| DomainTools.Identity.AdminContact.Email.value | String | The Email value of the administrator contact. |
| DomainTools.Identity.AdminContact.Email.count | Number | The Email count of the administrator contact. |
| DomainTools.Identity.AdminContact.Name.value | String | The name value of the administrator contact. |
| DomainTools.Identity.AdminContact.Name.count | Number | The name count of the administrator contact. |
| DomainTools.Identity.AdminContact.Phone.value | String | The phone value of the administrator contact. |
| DomainTools.Identity.AdminContact.Phone.count | Number | The phone count of the administrator contact. |
| DomainTools.Identity.TechnicalContact.Country.value | String | The country value of the technical contact. |
| DomainTools.Identity.TechnicalContact.Country.count | Number | The country count of the technical contact. |
| DomainTools.Identity.TechnicalContact.Email.value | String | The Email value of the technical contact. |
| DomainTools.Identity.TechnicalContact.Email.count | Number | The Email count of the technical contact. |
| DomainTools.Identity.TechnicalContact.Name.value | String | The name value of the technical Contact. |
| DomainTools.Identity.TechnicalContact.Name.count | Number | The name count of the technical contact. |
| DomainTools.Identity.TechnicalContact.Phone.value | String | The phone value of the technical contact. |
| DomainTools.Identity.TechnicalContact.Phone.count | Number | The phone count of the technical contact. |
| DomainTools.Identity.BillingContact.Country.value | String | The country value of the billing contact. |
| DomainTools.Identity.BillingContact.Country.count | Number | The country count of the billing contact. |
| DomainTools.Identity.BillingContact.Email.value | String | The Email value of the billing contact. |
| DomainTools.Identity.BillingContact.Email.count | Number | The Email count of the billing contact. |
| DomainTools.Identity.BillingContact.Name.value | String | The name value of the billing contact. |
| DomainTools.Identity.BillingContact.Name.count | Number | The name count of the billing contact. |
| DomainTools.Identity.BillingContact.Phone.value | String | The phone value of the billing contact. |
| DomainTools.Identity.BillingContact.Phone.count | Number | The phone count of the billing contact. |
| DomainTools.Identity.EmailDomains | String | The Email Domains. |
| DomainTools.Identity.AdditionalWhoisEmails.value | String | The value of the Additional Whois Emails record. |
| DomainTools.Identity.AdditionalWhoisEmails.count | Number | The count of the Additional Whois Emails record. |
| DomainTools.Registration.DomainRegistrant | String | The registrant of the domain. |
| DomainTools.Registration.RegistrarStatus | String | The status of the registrar. |
| DomainTools.Registration.DomainStatus | Boolean | The active status of the domain. |
| DomainTools.Registration.CreateDate | Date | The date the domain was created. |
| DomainTools.Registration.ExpirationDate | Date | The expiration date of the domain. |
| DomainTools.Hosting.IPAddresses.address.value | String | The address value of IP addresses. |
| DomainTools.Hosting.IPAddresses.address.count | Number | The address count of IP addresses. |
| DomainTools.Hosting.IPAddresses.asn.value | String | The ASN value of IP addresses. |
| DomainTools.Hosting.IPAddresses.asn.count | Number | The ASN count of IP addresses. |
| DomainTools.Hosting.IPAddresses.country_code.value | String | The country code value of IP addresses. |
| DomainTools.Hosting.IPAddresses.country_code.count | Number | The country code count of IP addresses. |
| DomainTools.Hosting.IPAddresses.isp.value | String | The ISP value of IP addresses. |
| DomainTools.Hosting.IPAddresses.isp.count | Number | The ISP count of IP addresses. |
| DomainTools.Hosting.IPCountryCode | String | The country code of the IP address. |
| DomainTools.Hosting.MailServers.domain.value | String | The domain value of the Mail Servers. |
| DomainTools.Hosting.MailServers.domain.count | Number | The domain count of the Mail Servers. |
| DomainTools.Hosting.MailServers.host.value | String | The host value of the Mail Servers. |
| DomainTools.Hosting.MailServers.host.count | Number | The host count of the Mail Servers. |
| DomainTools.Hosting.MailServers.ip.value | String | The IP value of the Mail Servers. |
| DomainTools.Hosting.MailServers.ip.count | Number | The IP count of the Mail Servers. |
| DomainTools.Hosting.SPFRecord | String | The SPF Record. |
| DomainTools.Hosting.NameServers.domain.value | String | The domain value of the domain NameServers. |
| DomainTools.Hosting.NameServers.domain.count | Number | The domain count of the domain NameServers. |
| DomainTools.Hosting.NameServers.host.value | String | The host value of the domain NameServers. |
| DomainTools.Hosting.NameServers.host.count | Number | The host count of the domain NameServers. |
| DomainTools.Hosting.NameServers.ip.value | String | The IP value of the domain NameServers. |
| DomainTools.Hosting.NameServers.ip.count | Number | The IP count of domain NameServers. |
| DomainTools.Hosting.SSLCertificate.hash.value | String | The hash value of the SSL certificate. |
| DomainTools.Hosting.SSLCertificate.hash.count | Number | The hash count of the SSL certificate. |
| DomainTools.Hosting.SSLCertificate.organization.value | String | The organization value of the SSL certificate. |
| DomainTools.Hosting.SSLCertificate.organization.count | Number | The organization count of the SSL certificate information. |
| DomainTools.Hosting.SSLCertificate.subject.value | String | The subject value of the SSL certificate information. |
| DomainTools.Hosting.SSLCertificate.subject.count | Number | The subject count of the SSL certificate information. |
| DomainTools.Hosting.RedirectsTo.value | String | The Redirects To Value of the domain. |
| DomainTools.Hosting.RedirectsTo.count | Number | The Redirects To Count of the domain. |
| DomainTools.Analytics.GoogleAdsenseTrackingCode | Number | The tracking code of Google Adsense. |
| DomainTools.Analytics.GoogleAnalyticTrackingCode | Number | The tracking code of Google Analytics. |
| DomainTools.Domains.Analytics.GA4TrackingCode | Number | The tracking code of ga4. |
| DomainTools.Domains.Analytics.GTMTrackingCode | Number | The tracking code of gtm. |
| DomainTools.Domains.Analytics.FBTrackingCode | Number | The tracking code of fb. |
| DomainTools.Domains.Analytics.HotJarTrackingCode | Number | The tracking code of Hot Jar. |
| DomainTools.Domains.Analytics.BaiduTrackingCode | Number | The tracking code of Baidu. |
| DomainTools.Domains.Analytics.YandexTrackingCode | Number | The tracking code of Yandex. |
| DomainTools.Domains.Analytics.MatomoTrackingCode | Number | The tracking code of Matomo. |
| DomainTools.Domains.Analytics.StatcounterProjectTrackingCode | Number | The tracking code of Stat Counter Project. |
| DomainTools.Domains.Analytics.StatcounterSecurityTrackingCode | Number | The tracking code of Stat Counter Security. |
| DomainTools.WebsiteTitle | Number | The website title. |
| DomainTools.FirstSeen | Number | The date the domain was first seen. |
| DomainTools.ServerType | Number | The server type. |
| DBotScore.Indicator | String | The indicator of the DBotScore. |
| DBotScore.Type | String | The indicator type of the DBotScore. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |

### domaintoolsiris-analytics

***
Displays DomainTools Analytic data in a markdown format table.

#### Base Command

`domaintoolsiris-analytics`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name to display. | Required |
| include_context | Include the enrich results in Context Data. Defaults to true. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The name of the domain. |
| Domain.DNS | String | The DNS of the domain. |
| Domain.DomainStatus | Boolean | The status of the domain. |
| Domain.CreationDate | Date | The creation date of the domain. |
| Domain.ExpirationDate | Date | The expiration date of the domain. |
| Domain.NameServers | String | The NameServers of the domain. |
| Domain.Registrant.Country | String | The registrant country of the domain. |
| Domain.Registrant.Email | String | The registrant Email of the domain. |
| Domain.Registrant.Name | String | The registrant name of the domain. |
| Domain.Registrant.Phone | String | The registrant phone number of the domain. |
| Domain.Malicious.Vendor | String | The vendor that classified the domain as malicious. |
| Domain.Malicious.Description | String | The description as to why the domain was found malicious. |
| DomainTools.Domains.Name | String | The domain name in DomainTools. |
| DomainTools.Domains.LastEnriched | Date | The last Time DomainTools enriched domain data. |
| DomainTools.Domains.Analytics.OverallRiskScore | Number | The DomainTools Overall Risk Score. |
| DomainTools.Domains.Analytics.ProximityRiskScore | Number | The DomainTools Proximity Risk Score. |
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.RiskScore | Number | The DomainTools Threat Profile Risk Score. |
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Threats | String | The DomainTools Threat Profile Threats. |
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Evidence | String | The DomainTools Threat Profile Evidence. |
| DomainTools.Domains.Analytics.WebsiteResponseCode | Number | The Website Response Code. |
| DomainTools.Domains.Analytics.Tags | String | The tags in DomainTools. |
| DomainTools.Domains.Identity.RegistrantName | String | The name of the registrant. |
| DomainTools.Domains.Identity.RegistrantOrg | String | The organization of the registrant. |
| DomainTools.Domains.Identity.RegistrantContact.Country.value | String | The country value of the registrant contact. |
| DomainTools.Domains.Identity.RegistrantContact.Country.count | Number | The country count of the registrant contact. |
| DomainTools.Domains.Identity.RegistrantContact.Email.value | String | The Email value of the registrant contact. |
| DomainTools.Domains.Identity.RegistrantContact.Email.count | Number | The Email count of the registrant contact. |
| DomainTools.Domains.Identity.RegistrantContact.Name.value | String | The name value of the registrant contact. |
| DomainTools.Domains.Identity.RegistrantContact.Name.count | Number | The Name count of the registrant contact. |
| DomainTools.Domains.Identity.RegistrantContact.Phone.value | String | The phone value of the registrant contact. |
| DomainTools.Domains.Identity.RegistrantContact.Phone.count | Number | The phone count of the registrant contact. |
| DomainTools.Domains.Identity.SOAEmail | String | The SOA record Email. |
| DomainTools.Domains.Identity.SSLCertificateEmail | String | The email of the SSL certificate. |
| DomainTools.Domains.Identity.AdminContact.Country.value | String | The country value of the administrator contact. |
| DomainTools.Domains.Identity.AdminContact.Country.count | Number | The country count of the administrator contact. |
| DomainTools.Domains.Identity.AdminContact.Email.value | String | The Email value of the administrator contact. |
| DomainTools.Domains.Identity.AdminContact.Email.count | Number | The Email count of the administrator contact. |
| DomainTools.Domains.Identity.AdminContact.Name.value | String | The name value of the administrator contact. |
| DomainTools.Domains.Identity.AdminContact.Name.count | Number | The name count of administrator contact. |
| DomainTools.Domains.Identity.AdminContact.Phone.value | String | The phone value of the administrator contact. |
| DomainTools.Domains.Identity.AdminContact.Phone.count | Number | The phone count of the administrator contact. |
| DomainTools.Domains.Identity.TechnicalContact.Country.value | String | The country value of the technical contact. |
| DomainTools.Domains.Identity.TechnicalContact.Country.count | Number | The country count of the technical contact. |
| DomainTools.Domains.Identity.TechnicalContact.Email.value | String | The Email value of the technical contact. |
| DomainTools.Domains.Identity.TechnicalContact.Email.count | Number | The Email count of the technical contact. |
| DomainTools.Domains.Identity.TechnicalContact.Name.value | String | The name value of the technical contact. |
| DomainTools.Domains.Identity.TechnicalContact.Name.count | Number | The name count of the technical contact. |
| DomainTools.Domains.Identity.TechnicalContact.Phone.value | String | The phone value of the technical contact. |
| DomainTools.Domains.Identity.TechnicalContact.Phone.count | Number | The phone count of the technical contact. |
| DomainTools.Domains.Identity.BillingContact.Country.value | String | The country value of the billing contact. |
| DomainTools.Domains.Identity.BillingContact.Country.count | Number | The country count of the billing contact. |
| DomainTools.Domains.Identity.BillingContact.Email.value | String | The email value of the billing contact. |
| DomainTools.Domains.Identity.BillingContact.Email.count | Number | The email count of the billing contact. |
| DomainTools.Domains.Identity.BillingContact.Name.value | String | The name value of the billing contact. |
| DomainTools.Domains.Identity.BillingContact.Name.count | Number | The name count of the billing contact. |
| DomainTools.Domains.Identity.BillingContact.Phone.value | String | The phone value of the billing contact. |
| DomainTools.Domains.Identity.BillingContact.Phone.count | Number | The phone count of the billing contact. |
| DomainTools.Domains.Identity.EmailDomains | String | The domain of the Email. |
| DomainTools.Domains.Identity.AdditionalWhoisEmails.value | String | The value of the Additional Whois Emails. |
| DomainTools.Domains.Identity.AdditionalWhoisEmails.count | Number | The count of the Additional Whois Emails. |
| DomainTools.Domains.Registration.DomainRegistrant | String | The registrant of the domain. |
| DomainTools.Domains.Registration.RegistrarStatus | String | The status of the registrar. |
| DomainTools.Domains.Registration.DomainStatus | Boolean | The active status of the domain. |
| DomainTools.Domains.Registration.CreateDate | Date | The date the domain was created. |
| DomainTools.Domains.Registration.ExpirationDate | Date | The date the domain expires. |
| DomainTools.Domains.Hosting.IPAddresses.address.value | String | The address values of the IP addresses. |
| DomainTools.Domains.Hosting.IPAddresses.address.count | Number | The address counts of the IP addresses. |
| DomainTools.Domains.Hosting.IPAddresses.asn.value | String | The ASN values of the IP addresses. |
| DomainTools.Domains.Hosting.IPAddresses.asn.count | Number | The ASN counts of the IP addresses. |
| DomainTools.Domains.Hosting.IPAddresses.country_code.value | String | The country code values of the IP addresses. |
| DomainTools.Domains.Hosting.IPAddresses.country_code.count | Number | The country code counts of the IP addresses. |
| DomainTools.Domains.Hosting.IPAddresses.isp.value | String | IP Addresses Info isp value. |
| DomainTools.Domains.Hosting.IPAddresses.isp.count | Number | IP Addresses Info isp count. |
| DomainTools.Domains.Hosting.IPCountryCode | String | IP Country Code. |
| DomainTools.Domains.Hosting.MailServers.domain.value | String | Mail Servers Info domain value. |
| DomainTools.Domains.Hosting.MailServers.domain.count | Number | Mail Servers Info domain count. |
| DomainTools.Domains.Hosting.MailServers.host.value | String | Mail Servers Info host value. |
| DomainTools.Domains.Hosting.MailServers.host.count | Number | Mail Servers Info host count. |
| DomainTools.Domains.Hosting.MailServers.ip.value | String | Mail Servers Info ip value. |
| DomainTools.Domains.Hosting.MailServers.ip.count | Number | Mail Servers Info ip count. |
| DomainTools.Domains.Hosting.SPFRecord | String | The SPF record. |
| DomainTools.Domains.Hosting.NameServers.domain.value | String | The domain value of the DomainTools Domains NameServers. |
| DomainTools.Domains.Hosting.NameServers.domain.count | Number | The domain count of the DomainTools Domains NameServers. |
| DomainTools.Domains.Hosting.NameServers.host.value | String | The host value of the DomainTools Domains NameServers. |
| DomainTools.Domains.Hosting.NameServers.host.count | Number | The host count of the DomainTools Domains NameServers. |
| DomainTools.Domains.Hosting.NameServers.ip.value | String | The IP value of the DomainTools Domains NameServers. |
| DomainTools.Domains.Hosting.NameServers.ip.count | Number | The IP count of the DomainTools Domains NameServers. |
| DomainTools.Domains.Hosting.SSLCertificate.hash.value | String | The hash value of the SSL certificate. |
| DomainTools.Domains.Hosting.SSLCertificate.hash.count | Number | The hash count of the SSL certificate. |
| DomainTools.Domains.Hosting.SSLCertificate.organization.value | String | The organization value of the SSL certificate. |
| DomainTools.Domains.Hosting.SSLCertificate.organization.count | Number | The organization count of the SSL certificate. |
| DomainTools.Domains.Hosting.SSLCertificate.subject.value | String | The subject value of the SSL certificate. |
| DomainTools.Domains.Hosting.SSLCertificate.subject.count | Number | The subject count of the SSL certificate. |
| DomainTools.Domains.Hosting.RedirectsTo.value | String | The Redirects To value of the domain. |
| DomainTools.Domains.Hosting.RedirectsTo.count | Number | The Redirects To count of the domain. |
| DomainTools.Domains.Analytics.GoogleAdsenseTrackingCode | Number | The tracking code of Google Adsense. |
| DomainTools.Analytics.GoogleAnalyticTrackingCode | Number | The tracking code of Google Analytics. |
| DomainTools.Domains.Analytics.GA4TrackingCode | Number | The tracking code of ga4. |
| DomainTools.Domains.Analytics.GTMTrackingCode | Number | The tracking code of gtm. |
| DomainTools.Domains.Analytics.FBTrackingCode | Number | The tracking code of fb. |
| DomainTools.Domains.Analytics.HotJarTrackingCode | Number | The tracking code of Hot Jar. |
| DomainTools.Domains.Analytics.BaiduTrackingCode | Number | The tracking code of Baidu. |
| DomainTools.Domains.Analytics.YandexTrackingCode | Number | The tracking code of Yandex. |
| DomainTools.Domains.Analytics.MatomoTrackingCode | Number | The tracking code of Matomo. |
| DomainTools.Domains.Analytics.StatcounterProjectTrackingCode | Number | The tracking code of Stat Counter Project. |
| DomainTools.Domains.Analytics.StatcounterSecurityTrackingCode | Number | The tracking code of Stat Counter Security. |
| DBotScore.Indicator | String | The DBotScore indicator. |
| DBotScore.Type | String | The indicator type of the DBotScore. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |

### domaintoolsiris-threat-profile

***
Displays DomainTools Threat Profile data in a markdown format table.

#### Base Command

`domaintoolsiris-threat-profile`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | The name of the domain. |
| Domain.DNS | String | The DNS of the domain. |
| Domain.DomainStatus | Boolean | The status of the domain. |
| Domain.CreationDate | Date | The creation date of the domain. |
| Domain.ExpirationDate | Date | The expiration date of the domain. |
| Domain.NameServers | String | The NameServers of the domain. |
| Domain.Registrant.Country | String | The registrant country of the domain. |
| Domain.Registrant.Email | String | The Email of the registrant domain. |
| Domain.Registrant.Name | String | The registrant name of the domain. |
| Domain.Registrant.Phone | String | The phone value of the registrant domain. |
| Domain.Malicious.Vendor | String | Vendor that classified the domain as malicious. |
| Domain.Malicious.Description | String | The  description as to why the domain was found to be malicious. |
| DomainTools.Domains.Name | String | The DomainTools domain name. |
| DomainTools.Domains.LastEnriched | Date | The last time DomainTools enriched the domain data. |
| DomainTools.Domains.Analytics.OverallRiskScore | Number | The DomainTools Overall Risk Score. |
| DomainTools.Domains.Analytics.ProximityRiskScore | Number | The DomainTools Proximity Risk Score. |
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.RiskScore | Number | The DomainTools Threat Profile Risk Score. |
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Threats | String | The DomainTools Threat Profile Threats. |
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Evidence | String | The DomainTools Threat Profile Evidence. |
| DomainTools.Domains.Analytics.WebsiteResponseCode | Number | The response code of the Website. |
| DomainTools.Domains.Analytics.Tags | String | The DomainTools Tags. |
| DomainTools.Domains.Identity.RegistrantName | String | The name of the registrant. |
| DomainTools.Domains.Identity.RegistrantOrg | String | The organization of the registrant. |
| DomainTools.Domains.Identity.RegistrantContact.Country.value | String | The country value of the registrant contact. |
| DomainTools.Domains.Identity.RegistrantContact.Country.count | Number | The county count of the registrant contact. |
| DomainTools.Domains.Identity.RegistrantContact.Email.value | String | The Email value of the registrant contact. |
| DomainTools.Domains.Identity.RegistrantContact.Email.count | Number | The Email count of the registrant contact. |
| DomainTools.Domains.Identity.RegistrantContact.Name.value | String | The name value of the registrant contact. |
| DomainTools.Domains.Identity.RegistrantContact.Name.count | Number | The name count of the registrant contact. |
| DomainTools.Domains.Identity.RegistrantContact.Phone.value | String | The phone value of the registrant contact. |
| DomainTools.Domains.Identity.RegistrantContact.Phone.count | Number | The phone count of the registrant contact. |
| DomainTools.Domains.Identity.SOAEmail | String | The SOA record Email. |
| DomainTools.Domains.Identity.SSLCertificateEmail | String | The SSL certificate Email. |
| DomainTools.Domains.Identity.AdminContact.Country.value | String | The country value of the administrator contact. |
| DomainTools.Domains.Identity.AdminContact.Country.count | Number | The country count of the administrator contact. |
| DomainTools.Domains.Identity.AdminContact.Email.value | String | The Email value of the administrator contact. |
| DomainTools.Domains.Identity.AdminContact.Email.count | Number | The Email count of the administrator contact. |
| DomainTools.Domains.Identity.AdminContact.Name.value | String | The name value of the administrator contact. |
| DomainTools.Domains.Identity.AdminContact.Name.count | Number | The name count of the administrator contact. |
| DomainTools.Domains.Identity.AdminContact.Phone.value | String | The phone value of the administrator contact. |
| DomainTools.Domains.Identity.AdminContact.Phone.count | Number | The phone count of the administrator contact. |
| DomainTools.Domains.Identity.TechnicalContact.Country.value | String | The country value of the technical contact. |
| DomainTools.Domains.Identity.TechnicalContact.Country.count | Number | The country count of the technical contact. |
| DomainTools.Domains.Identity.TechnicalContact.Email.value | String | The Email value of the technical contact. |
| DomainTools.Domains.Identity.TechnicalContact.Email.count | Number | The Email count of the technical contact. |
| DomainTools.Domains.Identity.TechnicalContact.Name.value | String | The name value of the technical contact. |
| DomainTools.Domains.Identity.TechnicalContact.Name.count | Number | The name count of the technical contact. |
| DomainTools.Domains.Identity.TechnicalContact.Phone.value | String | The phone value of the technical contact. |
| DomainTools.Domains.Identity.TechnicalContact.Phone.count | Number | The phone count of the technical contact. |
| DomainTools.Domains.Identity.BillingContact.Country.value | String | The country value of the billing contact. |
| DomainTools.Domains.Identity.BillingContact.Country.count | Number | The country count of the billing contact. |
| DomainTools.Domains.Identity.BillingContact.Email.value | String | The Email value of the billing contact. |
| DomainTools.Domains.Identity.BillingContact.Email.count | Number | The Email count of the billing contact. |
| DomainTools.Domains.Identity.BillingContact.Name.value | String | The name value of the billing contact. |
| DomainTools.Domains.Identity.BillingContact.Name.count | Number | The name count of the billing contact. |
| DomainTools.Domains.Identity.BillingContact.Phone.value | String | The phone value of the billing contact. |
| DomainTools.Domains.Identity.BillingContact.Phone.count | Number | The phone count of the billing contact. |
| DomainTools.Domains.Identity.EmailDomains | String | The Email domains. |
| DomainTools.Domains.Identity.AdditionalWhoisEmails.value | String | The value of the Additional Whois Emails. |
| DomainTools.Domains.Identity.AdditionalWhoisEmails.count | Number | The count of the Additional Whois Emails. |
| DomainTools.Domains.Registration.DomainRegistrant | String | The registrant of the domain. |
| DomainTools.Domains.Registration.RegistrarStatus | String | The status of the registrar. |
| DomainTools.Domains.Registration.DomainStatus | Boolean | The active status of the domain. |
| DomainTools.Domains.Registration.CreateDate | Date | The date the domain was created. |
| DomainTools.Domains.Registration.ExpirationDate | Date | The expiry date of the domain. |
| DomainTools.Domains.Hosting.IPAddresses.address.value | String | The address value of the IP Addresses. |
| DomainTools.Domains.Hosting.IPAddresses.address.count | Number | The address count of the IP Addresses. |
| DomainTools.Domains.Hosting.IPAddresses.asn.value | String | The ASN value of the IP Addresses. |
| DomainTools.Domains.Hosting.IPAddresses.asn.count | Number | The ASN count of the IP Addresses. |
| DomainTools.Domains.Hosting.IPAddresses.country_code.value | String | The country code of the IP Addresses. |
| DomainTools.Domains.Hosting.IPAddresses.country_code.count | Number | The country code count of the IP Addresses. |
| DomainTools.Domains.Hosting.IPAddresses.isp.value | String | ISP value of the IP Addresses. |
| DomainTools.Domains.Hosting.IPAddresses.isp.count | Number | The ISP count of the IP Addresses. |
| DomainTools.Domains.Hosting.IPCountryCode | String | The country code of the IP address. |
| DomainTools.Domains.Hosting.MailServers.domain.value | String | The domain value of the Mail Servers. |
| DomainTools.Domains.Hosting.MailServers.domain.count | Number | The domain count of the Mail Servers. |
| DomainTools.Domains.Hosting.MailServers.host.value | String | The host value of the Mail Servers. |
| DomainTools.Domains.Hosting.MailServers.host.count | Number | The host count of the Mail Servers. |
| DomainTools.Domains.Hosting.MailServers.ip.value | String | The IP value of the Mail Servers. |
| DomainTools.Domains.Hosting.MailServers.ip.count | Number | The IP count of the Mail Servers. |
| DomainTools.Domains.Hosting.SPFRecord | String | The SPF Record. |
| DomainTools.Domains.Hosting.NameServers.domain.value | String | The domain value of the DomainTools Domains NameServers. |
| DomainTools.Domains.Hosting.NameServers.domain.count | Number | The domain count of the DomainTools Domains NameServers. |
| DomainTools.Domains.Hosting.NameServers.host.value | String | The host value of the DomainTools Domains NameServers. |
| DomainTools.Domains.Hosting.NameServers.host.count | Number | The host count of the DomainTools Domains NameServers. |
| DomainTools.Domains.Hosting.NameServers.ip.value | String | The IP value of the DomainTools Domains NameServers. |
| DomainTools.Domains.Hosting.NameServers.ip.count | Number | The IP count of the DomainTools Domains NameServers. |
| DomainTools.Domains.Hosting.SSLCertificate.hash.value | String | The hash value of the SSL certificate. |
| DomainTools.Domains.Hosting.SSLCertificate.hash.count | Number | The hash count of the SSL certificate. |
| DomainTools.Domains.Hosting.SSLCertificate.organization.value | String | The organization value of the SSL certificate. |
| DomainTools.Domains.Hosting.SSLCertificate.organization.count | Number | The organization count of the SSL certificate. |
| DomainTools.Domains.Hosting.SSLCertificate.subject.value | String | The subject value of the SSL certificate. |
| DomainTools.Domains.Hosting.SSLCertificate.subject.count | Number | The subject count of the SSL certificate. |
| DomainTools.Domains.Hosting.RedirectsTo.value | String | The Redirects To value of the domain. |
| DomainTools.Domains.Hosting.RedirectsTo.count | Number | The Redirects To count of the domain. |
| DomainTools.Domains.Analytics.GoogleAdsenseTrackingCode | Number | The tracking code of Google Adsense. |
| DomainTools.Analytics.GoogleAnalyticTrackingCode | Number | The tracking code of Google Analytics. |
| DomainTools.Domains.Analytics.GA4TrackingCode | Number | The tracking code of ga4. |
| DomainTools.Domains.Analytics.GTMTrackingCode | Number | The tracking code of gtm. |
| DomainTools.Domains.Analytics.FBTrackingCode | Number | The tracking code of fb. |
| DomainTools.Domains.Analytics.HotJarTrackingCode | Number | The tracking code of Hot Jar. |
| DomainTools.Domains.Analytics.BaiduTrackingCode | Number | The tracking code of Baidu. |
| DomainTools.Domains.Analytics.YandexTrackingCode | Number | The tracking code of Yandex. |
| DomainTools.Domains.Analytics.MatomoTrackingCode | Number | The tracking code of Matomo. |
| DomainTools.Domains.Analytics.StatcounterProjectTrackingCode | Number | The tracking code of Stat Counter Project. |
| DomainTools.Domains.Analytics.StatcounterSecurityTrackingCode | Number | The tracking code of Stat Counter Security. |
| DBotScore.Indicator | String | The DBotScore indicator. |
| DBotScore.Type | String | The indicator type of the DBotScore. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |

### domaintoolsiris-pivot

***
Pivot on connected infrastructure (IP, email, SSL), or import domains from Iris Investigate using a search hash. Retrieves up to 5000 domains at a time. Optionally exclude results from context with include_context=false.

#### Base Command

`domaintoolsiris-pivot`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | The IP Address. | Optional |
| email | The Email Address. | Optional |
| nameserver_ip | The Name Server IP Address. | Optional |
| ssl_hash | The hash of the SSL. | Optional |
| nameserver_host | The fully-qualified host name of the name server. For example, ns1.domaintools.net. | Optional |
| mailserver_host | The fully-qualified host name of the mail server. For example, mx.domaintools.net. | Optional |
| email_domain | Only the domain portion of a Whois or DNS SOA email address. | Optional |
| nameserver_domain | Registered domain portion of the name server. | Optional |
| registrar | Exact match to the Whois registrar field. | Optional |
| registrant | Exact match to the Whois registrant field. | Optional |
| registrant_org | Exact match to the Whois registrant organization field. | Optional |
| tagged_with_any | Comma-separated list of Iris Investigate tags. Returns domains tagged with any of the tags in a list. | Optional |
| tagged_with_all | Comma-separated list of tags. Only returns domains tagged with the full list of tags. | Optional |
| mailserver_domain | Only the registered domain portion of the mail server (domaintools.net). | Optional |
| mailserver_ip | IP address of the mail server. | Optional |
| redirect_domain | Find domains observed to redirect to another domain name. | Optional |
| ssl_org | Exact match to the organization name on the SSL certificate. | Optional |
| ssl_subject | Subject field from the SSL certificate. | Optional |
| ssl_email | Email address from the SSL certificate. | Optional |
| google_analytics | Domains with a Google Analytics tracking code. | Optional |
| adsense | Domains with a Google AdSense tracking code. | Optional |
| search_hash | Encoded search from the Iris UI. | Optional |
| include_context | Include the results of the pivot in Context Data. Defaults to true. Possible values are: true, false. Default is true. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DomainTools.Pivots.PivotedDomains.Name | String | The DomainTools Domain Name. |
| DomainTools.Pivots.PivotedDomains.LastEnriched | Date | The last time DomainTools enriched the domain data. |
| DomainTools.Pivots.PivotedDomains.Analytics.OverallRiskScore | Number | The DomainTools Overall Risk Score. |
| DomainTools.Pivots.PivotedDomains.Analytics.ProximityRiskScore | Number | The DomainTools Proximity Risk Score. |
| DomainTools.Pivots.PivotedDomains.Analytics.ThreatProfileRiskScore.RiskScore | Number | The DomainTools Threat Profile Risk Score. |
| DomainTools.Pivots.PivotedDomains.Analytics.ThreatProfileRiskScore.Threats | String | The DomainTools Threat Profile Threats. |
| DomainTools.Pivots.PivotedDomains.Analytics.ThreatProfileRiskScore.Evidence | String | The DomainTools Threat Profile Evidence. |
| DomainTools.Pivots.PivotedDomains.Analytics.WebsiteResponseCode | Number | The response code of the website. |
| DomainTools.Pivots.PivotedDomains.Analytics.Tags | String | The DomainTools tags. |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantName | String | The name of the registrant. |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantOrg | String | The organization of the registrant. |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantContact.Country.value | String | The country value of the registrant contact. |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantContact.Country.count | Number | The country count of the registrant contact. |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantContact.Email.value | String | The Email value of the registrant contact. |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantContact.Email.count | Number | The Email count of the registrant contact. |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantContact.Name.value | String | The name value of the registrant contact. |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantContact.Name.count | Number | The name count of the registrant contact. |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantContact.Phone.value | String | The phone value of of the registrant contact. |
| DomainTools.Pivots.PivotedDomains.Identity.RegistrantContact.Phone.count | Number | The phone count of the registrant contact. |
| DomainTools.Pivots.PivotedDomains.Identity.SOAEmail | String | The SOA record Email. |
| DomainTools.Pivots.PivotedDomains.Identity.SSLCertificateEmail | String | The SSL certificate Email. |
| DomainTools.Pivots.PivotedDomains.Identity.AdminContact.Country.value | String | The country value of the administrator contact. |
| DomainTools.Pivots.PivotedDomains.Identity.AdminContact.Country.count | Number | The country count of the administrator contact. |
| DomainTools.Pivots.PivotedDomains.Identity.AdminContact.Email.value | String | The Email value of the administrator contact. |
| DomainTools.Pivots.PivotedDomains.Identity.AdminContact.Email.count | Number | The Email count of the administrator contact. |
| DomainTools.Pivots.PivotedDomains.Identity.AdminContact.Name.value | String | The name value of the administrator contact. |
| DomainTools.Pivots.PivotedDomains.Identity.AdminContact.Name.count | Number | The name count of the administrator contact. |
| DomainTools.Pivots.PivotedDomains.Identity.AdminContact.Phone.value | String | The phone value of the administrator contact. |
| DomainTools.Pivots.PivotedDomains.Identity.AdminContact.Phone.count | Number | The phone count of the administrator contact. |
| DomainTools.Pivots.PivotedDomains.Identity.TechnicalContact.Country.value | String | The country value of the technical contact. |
| DomainTools.Pivots.PivotedDomains.Identity.TechnicalContact.Country.count | Number | The country count of the technical contact. |
| DomainTools.Pivots.PivotedDomains.Identity.TechnicalContact.Email.value | String | The Email value of the technical contact. |
| DomainTools.Pivots.PivotedDomains.Identity.TechnicalContact.Email.count | Number | The Email count of the technical contact. |
| DomainTools.Pivots.PivotedDomains.Identity.TechnicalContact.Name.value | String | The name value of the technical contact. |
| DomainTools.Pivots.PivotedDomains.Identity.TechnicalContact.Name.count | Number | The name count of the technical contact. |
| DomainTools.Pivots.PivotedDomains.Identity.TechnicalContact.Phone.value | String | The phone value of the technical contact. |
| DomainTools.Pivots.PivotedDomains.Identity.TechnicalContact.Phone.count | Number | The phone count of the technical contact. |
| DomainTools.Pivots.PivotedDomains.Identity.BillingContact.Country.value | String | The country value of the billing contact. |
| DomainTools.Pivots.PivotedDomains.Identity.BillingContact.Country.count | Number | The country count of the billing contact. |
| DomainTools.Pivots.PivotedDomains.Identity.BillingContact.Email.value | String | The Email value of the billing contact. |
| DomainTools.Pivots.PivotedDomains.Identity.BillingContact.Email.count | Number | The Email count of the billing contact. |
| DomainTools.Pivots.PivotedDomains.Identity.BillingContact.Name.value | String | The Name value of the billing contact. |
| DomainTools.Pivots.PivotedDomains.Identity.BillingContact.Name.count | Number | The Name count of the billing contact. |
| DomainTools.Pivots.PivotedDomains.Identity.BillingContact.Phone.value | String | The phone value of the billing contact. |
| DomainTools.Pivots.PivotedDomains.Identity.BillingContact.Phone.count | Number | The phone count of the billing contact. |
| DomainTools.Pivots.PivotedDomains.Identity.EmailDomains | String | The Email domains. |
| DomainTools.Pivots.PivotedDomains.Identity.AdditionalWhoisEmails.value | String | The value of the Additional Whois Emails. |
| DomainTools.Pivots.PivotedDomains.Identity.AdditionalWhoisEmails.count | Number | The count of the Additional Whois Emails. |
| DomainTools.Pivots.PivotedDomains.Registration.DomainRegistrant | String | The Registrant of the domain. |
| DomainTools.Pivots.PivotedDomains.Registration.RegistrarStatus | String | The status of the registrar. |
| DomainTools.Pivots.PivotedDomains.Registration.DomainStatus | Boolean | The active status of the registrar. |
| DomainTools.Pivots.PivotedDomains.Registration.CreateDate | Date | The date the domain was created. |
| DomainTools.Pivots.PivotedDomains.Registration.ExpirationDate | Date | The Expiry date of the domain. |
| DomainTools.Pivots.PivotedDomains.Hosting.IPAddresses.address.value | String | The address value of IP addresses. |
| DomainTools.Pivots.PivotedDomains.Hosting.IPAddresses.address.count | Number | The address count of IP addresses. |
| DomainTools.Pivots.PivotedDomains.Hosting.IPAddresses.asn.value | String | The ASN value of IP addresses. |
| DomainTools.Pivots.PivotedDomains.Hosting.IPAddresses.asn.count | Number | The ASN count of IP addresses. |
| DomainTools.Pivots.PivotedDomains.Hosting.IPAddresses.country_code.value | String | The country code value of IP addresses. |
| DomainTools.Pivots.PivotedDomains.Hosting.IPAddresses.country_code.count | Number | The country code count of IP addresses. |
| DomainTools.Pivots.PivotedDomains.Hosting.IPAddresses.isp.value | String | The ISP value of IP addresses. |
| DomainTools.Pivots.PivotedDomains.Hosting.IPAddresses.isp.count | Number | The ISP count of IP addresses. |
| DomainTools.Pivots.PivotedDomains.Hosting.IPCountryCode | String | The country code of the IP address. |
| DomainTools.Pivots.PivotedDomains.Hosting.MailServers.domain.value | String | The domain value of the Mail Servers. |
| DomainTools.Pivots.PivotedDomains.Hosting.MailServers.domain.count | Number | The domain count of the Mail Servers. |
| DomainTools.Pivots.PivotedDomains.Hosting.MailServers.host.value | String | The host value of the Mail Servers. |
| DomainTools.Pivots.PivotedDomains.Hosting.MailServers.host.count | Number | The host count of the Mail Servers. |
| DomainTools.Pivots.PivotedDomains.Hosting.MailServers.ip.value | String | The IP address value of the Mail Servers. |
| DomainTools.Pivots.PivotedDomains.Hosting.MailServers.ip.count | Number | The IP address count of the Mail Servers. |
| DomainTools.Pivots.PivotedDomains.Hosting.SPFRecord | String | The SPF record Information. |
| DomainTools.Pivots.PivotedDomains.Hosting.NameServers.domain.value | String | The domain value of DomainTools Domains NameServers. |
| DomainTools.Pivots.PivotedDomains.Hosting.NameServers.domain.count | Number | The domain count of DomainTools Domains NameServers. |
| DomainTools.Pivots.PivotedDomains.Hosting.NameServers.host.value | String | The host value of DomainTools Domains NameServers. |
| DomainTools.Pivots.PivotedDomains.Hosting.NameServers.host.count | Number | The host count of DomainTools Domains NameServers. |
| DomainTools.Pivots.PivotedDomains.Hosting.NameServers.ip.value | String | The IP address value of DomainTools Domains NameServers. |
| DomainTools.Pivots.PivotedDomains.Hosting.NameServers.ip.count | Number | The IP address count of DomainTools Domains NameServers. |
| DomainTools.Pivots.PivotedDomains.Hosting.SSLCertificate.hash.value | String | The hash value of the SSL certificate. |
| DomainTools.Pivots.PivotedDomains.Hosting.SSLCertificate.hash.count | Number | The hash count of the SSL certificate. |
| DomainTools.Pivots.PivotedDomains.Hosting.SSLCertificate.organization.value | String | The organization value of the SSL certificate. |
| DomainTools.Pivots.PivotedDomains.Hosting.SSLCertificate.organization.count | Number | The organization count of the SSL certificate. |
| DomainTools.Pivots.PivotedDomains.Hosting.SSLCertificate.subject.value | String | The subject value of the SSL certificate. |
| DomainTools.Pivots.PivotedDomains.Hosting.SSLCertificate.subject.count | Number | The subject count of the SSL certificate. |
| DomainTools.Pivots.PivotedDomains.Hosting.RedirectsTo.value | String | The Redirects To value of the domain. |
| DomainTools.Pivots.PivotedDomains.Hosting.RedirectsTo.count | Number | The Redirects To count of the domain. |
| DomainTools.Pivots.PivotedDomains.Analytics.GoogleAdsenseTrackingCode | Number | The tracking code of Google Adsense. |
| DomainTools.Pivots.PivotedDomains.Analytics.GoogleAnalyticTrackingCode | Number | The tracking code Google Analytics. |

### domaintools-whois-history

***
The DomainTools Whois History API endpoint returns up to 100 historical Whois records associated with a domain name.

#### Base Command

`domaintools-whois-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A domain name to query (e.g. example.com). | Required |
| mode | options: list, count, check_existence. list: (default), return whois records. count: return how many total records are available. check_existence: return if any records exist. Default: list. Possible values are: list, count, check_existence. Default is list. | Optional |
| offset | numeric, the index from which to begin retrieving results. Default: 0. Default is 0. | Optional |
| limit | numeric, default: 100, max: 100, the total number of records to return. Default: 100. Default is 100. | Optional |
| sort | options: date_desc, date_asc. date_desc: (default), order records from newest to oldest. date_asc: sort order records from oldest to newest. Default: date_desc. Possible values are: date_desc, date_asc. Default is date_desc. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DomainTools.History.Value | unknown | Name of domain. |
| DomainTools.History.WhoisHistory | unknown | Domain Whois history data. |

### domaintools-hosting-history

***
Hosting History will list IP address, name server and registrar history.

#### Base Command

`domaintools-hosting-history`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A domain name to query (e.g. example.com). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DomainTools.History.Value | unknown | Name of domain. |
| DomainTools.History.IPHistory | unknown | Domain IP history data. |
| DomainTools.History.NameserverHistory | unknown | Domain Nameserver history data. |
| DomainTools.History.RegistrarHistory | unknown | Domain Registrar history data. |

### domaintools-reverse-whois

***
The DomainTools Reverse Whois API provides a list of domain names that share the same Registrant Information. You can enter terms that describe a domain owner, like an email address or a company name, and you’ll get a list of domain names that have your search terms listed in the Whois record.

#### Base Command

`domaintools-reverse-whois`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| terms | (default) List of one or more terms to search for in the Whois record, separated with the pipe character ( \| ). | Required |
| exclude | Domain names with Whois records that match these terms will be excluded from the result set. Separate multiple terms with the pipe character ( \| ). | Optional |
| onlyHistoricScope | Show only historic records. Possible values are: true, false. Default is false. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DomainTools.ReverseWhois.Value | unknown | Search term to reverse whois lookup on. |
| DomainTools.ReverseWhois.Results | unknown | List of results for reverse whois lookup. |

### domaintools-whois

***
The DomainTools Parsed Whois API provides parsed information extracted from the raw Whois record. The API is optimized to quickly retrieve the Whois record, group important data together and return a well-structured format. The Parsed Whois API is ideal for anyone wishing to search for, index, or cross-reference data from one or multiple Whois records.

#### Base Command

`domaintools-whois`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | A domain name or IP address (e.g. example.com or 192.168.1.1). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | unknown | Requested domain name. |
| Domain.Whois | unknown | Parsed Whois data. |
| Domain.WhoisRecords | unknown | Full Whois record. |

### domainRdap

***
Returns the most recent Domain-RDAP registration record.

#### Base Command

`domainRdap`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Specify the domain (e.g., mycompany.com). | Required |

#### Context Output

There is no context output for this command.
