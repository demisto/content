## DomainTools Iris Playbook
---

## Configure DomainTools Iris on Cortex XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
=======
A threat, intelligence, and investigation platform for domain names, IP addresses Email addresses, Name Severs, and so on.
This integration was integrated and tested with version xx of DomainTools Iris

## Configure DomainTools Iris on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for DomainTools Iris.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | API Username | True |
    | API Key | True |
    | High-Risk Threshold | True |
    | Young Domain Timeframe (within Days) | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### domain

***
Returns a complete profile of the domain.

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`domain`

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
| Domain.CreationDate | Date | The creation date. | 
| Domain.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.NameServers | String | The nameServers of the domain. | 
| Domain.Registrant.Country | String | The registrant country of the domain. | 
| Domain.Registrant.Email | String | The registrant email of the domain. | 
| Domain.Registrant.Name | String | The registrant name of the domain. | 
| Domain.Registrant.Phone | String | The registrant phone number of the domain. | 
| Domain.Malicious.Vendor | String | The vendor who classified the domain as malicious. | 
| Domain.Malicious.Description | String | The description as to why the domain was found to be malicious. | 
| DomainTools.Domains.Name | String | The domain name in DomainTools. | 
| DomainTools.Domains.LastEnriched | Date | The last Time DomainTools enriched domain data. | 
| DomainTools.Domains.Analytics.OverallRiskScore | Number | The Overall Risk Score in DomainTools. | 
| DomainTools.Domains.Analytics.ProximityRiskScore | Number | The Proximity Risk Score in DomainTools. | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.RiskScore | Number | The Threat Profile Risk Score in DomainTools. | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Threats | String | The threats of the Threat Profile Risk Score in DomainTools. | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Evidence | String | The Threat Profile Risk Score Evidence in DomainTools. | 
| DomainTools.Domains.Analytics.WebsiteResponseCode | Number | The Website Response Code in DomainTools. | 
| DomainTools.Domains.Analytics.AlexaRank | Number | The Alexa Rank in DomainTools. | 
| DomainTools.Domains.Analytics.Tags | String | The Tags in DomainTools. | 
| DomainTools.Domains.Identity.RegistrantName | String | The name of the registrant. | 
| DomainTools.Domains.Identity.RegistrantOrg | String | The organization of the registrant. | 
| DomainTools.Domains.Identity.RegistrantContact.Country.value | String | The country value of the registrant contact. | 
| DomainTools.Domains.Identity.RegistrantContact.Country.count | Number | The count of the registrant contact country. | 
| DomainTools.Domains.Identity.RegistrantContact.Email.value | String | The Email value of the registrant contact. | 
| DomainTools.Domains.Identity.RegistrantContact.Email.count | Number | The Email count of the registrant contact. | 
| DomainTools.Domains.Identity.RegistrantContact.Name.value | String | The name value of the registrant contact. | 
| DomainTools.Domains.Identity.RegistrantContact.Name.count | Number | The name count of the registrant contact. | 
| DomainTools.Domains.Identity.RegistrantContact.Phone.value | String | The phone value of the registrant contact. | 
| DomainTools.Domains.Identity.RegistrantContact.Phone.count | Number | The phone count of the registrant contact. | 
| DomainTools.Domains.Identity.SOAEmail | String | The SOA record of the Email. | 
| DomainTools.Domains.Identity.SSLCertificateEmail | String | The Email of the SSL certificate. | 
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
| DomainTools.Domains.Identity.TechnicalContact.Name.value | String | The name value of the technical Contact. | 
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
| DomainTools.Domains.Identity.EmailDomains | String | The Email Domains. | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails.value | String | The value of the Additional Whois Emails record. | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails.count | Number | The count of the Additional Whois Emails record. | 
| DomainTools.Domains.Registration.DomainRegistrant | String | The registrant of the domain. | 
| DomainTools.Domains.Registration.RegistrarStatus | String | The status of the registrar. | 
| DomainTools.Domains.Registration.DomainStatus | Boolean | The active status of the domain. | 
| DomainTools.Domains.Registration.CreateDate | Date | The date the domain was created. | 
| DomainTools.Domains.Registration.ExpirationDate | Date | The expiration date of the domain. | 
| DomainTools.Domains.Hosting.IPAddresses.address.value | String | The address value of IP addresses. | 
| DomainTools.Domains.Hosting.IPAddresses.address.count | Number | The address count of IP addresses. | 
| DomainTools.Domains.Hosting.IPAddresses.asn.value | String | The ASN value of IP addresses. | 
| DomainTools.Domains.Hosting.IPAddresses.asn.count | Number | The ASN count of IP addresses. | 
| DomainTools.Domains.Hosting.IPAddresses.country_code.value | String | The country code value of IP addresses. | 
| DomainTools.Domains.Hosting.IPAddresses.country_code.count | Number | The country code count of IP addresses. | 
| DomainTools.Domains.Hosting.IPAddresses.isp.value | String | The ISP value of IP addresses. | 
| DomainTools.Domains.Hosting.IPAddresses.isp.count | Number | The ISP count of IP addresses. | 
| DomainTools.Domains.Hosting.IPCountryCode | String | The country code of the IP address. | 
| DomainTools.Domains.Hosting.MailServers.domain.value | String | The domain value of the Mail Servers. | 
| DomainTools.Domains.Hosting.MailServers.domain.count | Number | The domain count of the Mail Servers. | 
| DomainTools.Domains.Hosting.MailServers.host.value | String | The host value of the Mail Servers. | 
| DomainTools.Domains.Hosting.MailServers.host.count | Number | The host count of the Mail Servers. | 
| DomainTools.Domains.Hosting.MailServers.ip.value | String | The IP value of the Mail Servers. | 
| DomainTools.Domains.Hosting.MailServers.ip.count | Number | The IP count of the Mail Servers. | 
| DomainTools.Domains.Hosting.SPFRecord | String | The SPF Record. | 
| DomainTools.Domains.Hosting.NameServers.domain.value | String | The domain value of the domain NameServers. | 
| DomainTools.Domains.Hosting.NameServers.domain.count | Number | The domain count of the domain NameServers. | 
| DomainTools.Domains.Hosting.NameServers.host.value | String | The host value of the domain NameServers. | 
| DomainTools.Domains.Hosting.NameServers.host.count | Number | The host count of the domain NameServers. | 
| DomainTools.Domains.Hosting.NameServers.ip.value | String | The IP value of the domain NameServers. | 
| DomainTools.Domains.Hosting.NameServers.ip.count | Number | The IP count of domain NameServers. | 
| DomainTools.Domains.Hosting.SSLCertificate.hash.value | String | The hash value of the SSL certificate. | 
| DomainTools.Domains.Hosting.SSLCertificate.hash.count | Number | The hash count of the SSL certificate. | 
| DomainTools.Domains.Hosting.SSLCertificate.organization.value | String | The organization value of the SSL certificate. | 
| DomainTools.Domains.Hosting.SSLCertificate.organization.count | Number | The organization count of the SSL certificate information. | 
| DomainTools.Domains.Hosting.SSLCertificate.subject.value | String | The subject value of the SSL certificate information. | 
| DomainTools.Domains.Hosting.SSLCertificate.subject.count | Number | The subject count of the SSL certificate information. | 
| DomainTools.Domains.Hosting.RedirectsTo.value | String | The Redirects To Value of the domain. | 
| DomainTools.Domains.Hosting.RedirectsTo.count | Number | The Redirects To Count of the domain. | 
| DomainTools.Domains.Analytics.GoogleAdsenseTrackingCode | Number | The tracking code of Google Adsense. | 
| DomainTools.Domains.Analytics.GoogleAnalyticTrackingCode | Number | The tracking code of Google Analytics. | 
| DBotScore.Indicator | String | The indicator of the DBotScore. | 
| DBotScore.Type | String | The indicator type of the DBotScore. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 

### domaintoolsiris-enrich

***
Returns a complete profile of the domain using Iris Enrich.

#### Base Command

`domaintoolsiris-enrich`

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
| Domain.CreationDate | Date | The creation date. | 
| Domain.ExpirationDate | Date | The expiration date of the domain. | 
| Domain.NameServers | String | The nameServers of the domain. | 
| Domain.Registrant.Country | String | The registrant country of the domain. | 
| Domain.Registrant.Email | String | The registrant email of the domain. | 
| Domain.Registrant.Name | String | The registrant name of the domain. | 
| Domain.Registrant.Phone | String | The registrant phone number of the domain. | 
| Domain.Malicious.Vendor | String | The vendor who classified the domain as malicious. | 
| Domain.Malicious.Description | String | The description as to why the domain was found to be malicious. | 
| DomainTools.Domains.Name | String | The domain name in DomainTools. | 
| DomainTools.Domains.LastEnriched | Date | The last Time DomainTools enriched domain data. | 
| DomainTools.Domains.Analytics.OverallRiskScore | Number | The Overall Risk Score in DomainTools. | 
| DomainTools.Domains.Analytics.ProximityRiskScore | Number | The Proximity Risk Score in DomainTools. | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.RiskScore | Number | The Threat Profile Risk Score in DomainTools. | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Threats | String | The threats of the Threat Profile Risk Score in DomainTools. | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Evidence | String | The Threat Profile Risk Score Evidence in DomainTools. | 
| DomainTools.Domains.Analytics.WebsiteResponseCode | Number | The Website Response Code in DomainTools. | 
| DomainTools.Domains.Analytics.AlexaRank | Number | The Alexa Rank in DomainTools. | 
| DomainTools.Domains.Analytics.Tags | String | The Tags in DomainTools. | 
| DomainTools.Domains.Identity.RegistrantName | String | The name of the registrant. | 
| DomainTools.Domains.Identity.RegistrantOrg | String | The organization of the registrant. | 
| DomainTools.Domains.Identity.RegistrantContact.Country.value | String | The country value of the registrant contact. | 
| DomainTools.Domains.Identity.RegistrantContact.Country.count | Number | The count of the registrant contact country. | 
| DomainTools.Domains.Identity.RegistrantContact.Email.value | String | The Email value of the registrant contact. | 
| DomainTools.Domains.Identity.RegistrantContact.Email.count | Number | The Email count of the registrant contact. | 
| DomainTools.Domains.Identity.RegistrantContact.Name.value | String | The name value of the registrant contact. | 
| DomainTools.Domains.Identity.RegistrantContact.Name.count | Number | The name count of the registrant contact. | 
| DomainTools.Domains.Identity.RegistrantContact.Phone.value | String | The phone value of the registrant contact. | 
| DomainTools.Domains.Identity.RegistrantContact.Phone.count | Number | The phone count of the registrant contact. | 
| DomainTools.Domains.Identity.SOAEmail | String | The SOA record of the Email. | 
| DomainTools.Domains.Identity.SSLCertificateEmail | String | The Email of the SSL certificate. | 
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
| DomainTools.Domains.Identity.TechnicalContact.Name.value | String | The name value of the technical Contact. | 
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
| DomainTools.Domains.Identity.EmailDomains | String | The Email Domains. | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails.value | String | The value of the Additional Whois Emails record. | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails.count | Number | The count of the Additional Whois Emails record. | 
| DomainTools.Domains.Registration.DomainRegistrant | String | The registrant of the domain. | 
| DomainTools.Domains.Registration.RegistrarStatus | String | The status of the registrar. | 
| DomainTools.Domains.Registration.DomainStatus | Boolean | The active status of the domain. | 
| DomainTools.Domains.Registration.CreateDate | Date | The date the domain was created. | 
| DomainTools.Domains.Registration.ExpirationDate | Date | The expiration date of the domain. | 
| DomainTools.Domains.Hosting.IPAddresses.address.value | String | The address value of IP addresses. | 
| DomainTools.Domains.Hosting.IPAddresses.address.count | Number | The address count of IP addresses. | 
| DomainTools.Domains.Hosting.IPAddresses.asn.value | String | The ASN value of IP addresses. | 
| DomainTools.Domains.Hosting.IPAddresses.asn.count | Number | The ASN count of IP addresses. | 
| DomainTools.Domains.Hosting.IPAddresses.country_code.value | String | The country code value of IP addresses. | 
| DomainTools.Domains.Hosting.IPAddresses.country_code.count | Number | The country code count of IP addresses. | 
| DomainTools.Domains.Hosting.IPAddresses.isp.value | String | The ISP value of IP addresses. | 
| DomainTools.Domains.Hosting.IPAddresses.isp.count | Number | The ISP count of IP addresses. | 
| DomainTools.Domains.Hosting.IPCountryCode | String | The country code of the IP address. | 
| DomainTools.Domains.Hosting.MailServers.domain.value | String | The domain value of the Mail Servers. | 
| DomainTools.Domains.Hosting.MailServers.domain.count | Number | The domain count of the Mail Servers. | 
| DomainTools.Domains.Hosting.MailServers.host.value | String | The host value of the Mail Servers. | 
| DomainTools.Domains.Hosting.MailServers.host.count | Number | The host count of the Mail Servers. | 
| DomainTools.Domains.Hosting.MailServers.ip.value | String | The IP value of the Mail Servers. | 
| DomainTools.Domains.Hosting.MailServers.ip.count | Number | The IP count of the Mail Servers. | 
| DomainTools.Domains.Hosting.SPFRecord | String | The SPF Record. | 
| DomainTools.Domains.Hosting.NameServers.domain.value | String | The domain value of the domain NameServers. | 
| DomainTools.Domains.Hosting.NameServers.domain.count | Number | The domain count of the domain NameServers. | 
| DomainTools.Domains.Hosting.NameServers.host.value | String | The host value of the domain NameServers. | 
| DomainTools.Domains.Hosting.NameServers.host.count | Number | The host count of the domain NameServers. | 
| DomainTools.Domains.Hosting.NameServers.ip.value | String | The IP value of the domain NameServers. | 
| DomainTools.Domains.Hosting.NameServers.ip.count | Number | The IP count of domain NameServers. | 
| DomainTools.Domains.Hosting.SSLCertificate.hash.value | String | The hash value of the SSL certificate. | 
| DomainTools.Domains.Hosting.SSLCertificate.hash.count | Number | The hash count of the SSL certificate. | 
| DomainTools.Domains.Hosting.SSLCertificate.organization.value | String | The organization value of the SSL certificate. | 
| DomainTools.Domains.Hosting.SSLCertificate.organization.count | Number | The organization count of the SSL certificate information. | 
| DomainTools.Domains.Hosting.SSLCertificate.subject.value | String | The subject value of the SSL certificate information. | 
| DomainTools.Domains.Hosting.SSLCertificate.subject.count | Number | The subject count of the SSL certificate information. | 
| DomainTools.Domains.Hosting.RedirectsTo.value | String | The Redirects To Value of the domain. | 
| DomainTools.Domains.Hosting.RedirectsTo.count | Number | The Redirects To Count of the domain. | 
| DomainTools.Domains.Analytics.GoogleAdsenseTrackingCode | Number | The tracking code of Google Adsense. | 
| DomainTools.Domains.Analytics.GoogleAnalyticTrackingCode | Number | The tracking code of Google Analytics. | 
| DBotScore.Indicator | String | The indicator of the DBotScore. | 
| DBotScore.Type | String | The indicator type of the DBotScore. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 

### domaintoolsiris-analytics

***
Provides markdown table with DomainTools Analytic data

Notice: Submitting indicators using this command might make the indicator data publicly available. See the vendor’s documentation for more details.

#### Base Command

`domaintoolsiris-analytics`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | The domain name to display. | Required | 

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
| DomainTools.Domains.Analytics.AlexaRank | Number | The Alexa Rank. | 
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
| DomainTools.Domains.Hosting.IPAddresses.isp.value | String | IP Addresses Info isp value | 
| DomainTools.Domains.Hosting.IPAddresses.isp.count | Number | IP Addresses Info isp count | 
| DomainTools.Domains.Hosting.IPCountryCode | String | IP Country Code | 
| DomainTools.Domains.Hosting.MailServers.domain.value | String | Mail Servers Info domain value | 
| DomainTools.Domains.Hosting.MailServers.domain.count | Number | Mail Servers Info domain count | 
| DomainTools.Domains.Hosting.MailServers.host.value | String | Mail Servers Info host value | 
| DomainTools.Domains.Hosting.MailServers.host.count | Number | Mail Servers Info host count | 
| DomainTools.Domains.Hosting.MailServers.ip.value | String | Mail Servers Info ip value | 
| DomainTools.Domains.Hosting.MailServers.ip.count | Number | Mail Servers Info ip count | 
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
| DomainTools.Domains.Analytics.GoogleAnalyticTrackingCode | Number | The tracking code of Google Analytics. | 
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
| DomainTools.Domains.Analytics.AlexaRank | Number | The Alexa Rank. | 
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
| DomainTools.Domains.Analytics.GoogleAnalyticTrackingCode | Number | The tracking code of Google Analytics. | 
| DBotScore.Indicator | String | The DBotScore indicator. | 
| DBotScore.Type | String | The indicator type of the DBotScore. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 

### domaintoolsiris-pivot

***
Returns data on domain IP addresses, Email Addresses, Name Server IP addresses, and so on.

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

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DomainTools.PivotedDomains.Name | String | DomainTools Domain Name | 
| DomainTools.PivotedDomains.LastEnriched | Date | Last Time DomainTools Enriched Domain Data | 
| DomainTools.PivotedDomains.Analytics.OverallRiskScore | Number | DomainTools Overall Risk Score | 
| DomainTools.PivotedDomains.Analytics.ProximityRiskScore | Number | DomainTools Proximity Risk Score | 
| DomainTools.PivotedDomains.Analytics.ThreatProfileRiskScore.RiskScore | Number | DomainTools Threat Profile Risk Score | 
| DomainTools.PivotedDomains.Analytics.ThreatProfileRiskScore.Threats | String | DomainTools Threat Profile Threats | 
| DomainTools.PivotedDomains.Analytics.ThreatProfileRiskScore.Evidence | String | DomainTools Threat Profile Evidence | 
| DomainTools.PivotedDomains.Analytics.WebsiteResponseCode | Number | Website Response Code | 
| DomainTools.PivotedDomains.Analytics.AlexaRank | Number | Alexa Rank | 
| DomainTools.PivotedDomains.Analytics.Tags | String | DomainTools Tags | 
| DomainTools.PivotedDomains.Identity.RegistrantName | String | Registrant Name | 
| DomainTools.PivotedDomains.Identity.RegistrantOrg | String | Registrant Org | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Country.value | String | Registrant Contact Country value | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Country.count | Number | Registrant Contact Country count | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Email.value | String | Registrant Contact Email value | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Email.count | Number | Registrant Contact Email count | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Name.value | String | Registrant Contact Name value | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Name.count | Number | Registrant Contact Name count | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Phone.value | String | Registrant Contact Phone value | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Phone.count | Number | Registrant Contact Phone count | 
| DomainTools.PivotedDomains.Identity.SOAEmail | String | SOA Record Email | 
| DomainTools.PivotedDomains.Identity.SSLCertificateEmail | String | SSL Certificate Email | 
| DomainTools.PivotedDomains.Identity.AdminContact.Country.value | String | Admin Contact Country value | 
| DomainTools.PivotedDomains.Identity.AdminContact.Country.count | Number | Admin Contact Country count | 
| DomainTools.PivotedDomains.Identity.AdminContact.Email.value | String | Admin Contact Email value | 
| DomainTools.PivotedDomains.Identity.AdminContact.Email.count | Number | Admin Contact Email count | 
| DomainTools.PivotedDomains.Identity.AdminContact.Name.value | String | Admin Contact Name value | 
| DomainTools.PivotedDomains.Identity.AdminContact.Name.count | Number | Admin Contact Name count | 
| DomainTools.PivotedDomains.Identity.AdminContact.Phone.value | String | Admin Contact Phone value | 
| DomainTools.PivotedDomains.Identity.AdminContact.Phone.count | Number | Admin Contact Phone count | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Country.value | String | Technical Contact Country value | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Country.count | Number | Technical Contact Country count | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Email.value | String | Technical Contact Email value | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Email.count | Number | Technical Contact Email count | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Name.value | String | Technical Contact Name value | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Name.count | Number | Technical Contact Name count | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Phone.value | String | Technical Contact Phone value | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Phone.count | Number | Technical Contact Phone count | 
| DomainTools.PivotedDomains.Identity.BillingContact.Country.value | String | Billing Contact Country value | 
| DomainTools.PivotedDomains.Identity.BillingContact.Country.count | Number | Billing Contact Country count | 
| DomainTools.PivotedDomains.Identity.BillingContact.Email.value | String | Billing Contact Email value | 
| DomainTools.PivotedDomains.Identity.BillingContact.Email.count | Number | Billing Contact Email count | 
| DomainTools.PivotedDomains.Identity.BillingContact.Name.value | String | Billing Contact Name value | 
| DomainTools.PivotedDomains.Identity.BillingContact.Name.count | Number | Billing Contact Name count | 
| DomainTools.PivotedDomains.Identity.BillingContact.Phone.value | String | Billing Contact Phone value | 
| DomainTools.PivotedDomains.Identity.BillingContact.Phone.count | Number | Billing Contact Phone count | 
| DomainTools.PivotedDomains.Identity.EmailDomains | String | Email Domains | 
| DomainTools.PivotedDomains.Identity.AdditionalWhoisEmails.value | String | Additional Whois Emails value | 
| DomainTools.PivotedDomains.Identity.AdditionalWhoisEmails.count | Number | Additional Whois Emails count | 
| DomainTools.PivotedDomains.Registration.DomainRegistrant | String | Domain Registrant | 
| DomainTools.PivotedDomains.Registration.RegistrarStatus | String | Registrar Status | 
| DomainTools.PivotedDomains.Registration.DomainStatus | Boolean | Domain Active Status | 
| DomainTools.PivotedDomains.Registration.CreateDate | Date | Create Date | 
| DomainTools.PivotedDomains.Registration.ExpirationDate | Date | Expiration Date | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.address.value | String | IP Addresses Info address value | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.address.count | Number | IP Addresses Info address count | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.asn.value | String | IP Addresses Info asn value | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.asn.count | Number | IP Addresses Info asn count | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.country_code.value | String | IP Addresses Info country_code value | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.country_code.count | Number | IP Addresses Info country_code count | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.isp.value | String | IP Addresses Info isp value | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.isp.count | Number | IP Addresses Info isp count | 
| DomainTools.PivotedDomains.Hosting.IPCountryCode | String | IP Country Code | 
| DomainTools.PivotedDomains.Hosting.MailServers.domain.value | String | Mail Servers Info domain value | 
| DomainTools.PivotedDomains.Hosting.MailServers.domain.count | Number | Mail Servers Info domain count | 
| DomainTools.PivotedDomains.Hosting.MailServers.host.value | String | Mail Servers Info host value | 
| DomainTools.PivotedDomains.Hosting.MailServers.host.count | Number | Mail Servers Info host count | 
| DomainTools.PivotedDomains.Hosting.MailServers.ip.value | String | Mail Servers Info ip value | 
| DomainTools.PivotedDomains.Hosting.MailServers.ip.count | Number | Mail Servers Info ip count | 
| DomainTools.PivotedDomains.Hosting.SPFRecord | String | SPF Record Info | 
| DomainTools.PivotedDomains.Hosting.NameServers.domain.value | String | DomainTools Domains NameServers domain value | 
| DomainTools.PivotedDomains.Hosting.NameServers.domain.count | Number | DomainTools Domains NameServers domain count | 
| DomainTools.PivotedDomains.Hosting.NameServers.host.value | String | DomainTools Domains NameServers host value | 
| DomainTools.PivotedDomains.Hosting.NameServers.host.count | Number | DomainTools Domains NameServers host count | 
| DomainTools.PivotedDomains.Hosting.NameServers.ip.value | String | DomainTools Domains NameServers ip value | 
| DomainTools.PivotedDomains.Hosting.NameServers.ip.count | Number | DomainTools Domains NameServers ip count | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.hash.value | String | SSL Certificate Info hash value | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.hash.count | Number | SSL Certificate Info hash count | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.organization.value | String | SSL Certificate Info organization value | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.organization.count | Number | SSL Certificate Info organization count | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.subject.value | String | SSL Certificate Info subject value | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.subject.count | Number | SSL Certificate Info subject count | 
| DomainTools.PivotedDomains.Hosting.RedirectsTo.value | String | Domains it Redirects To value | 
| DomainTools.PivotedDomains.Hosting.RedirectsTo.count | Number | Domains it Redirects To count | 
| DomainTools.PivotedDomains.Analytics.GoogleAdsenseTrackingCode | Number | Google Adsense Tracking Code | 
| DomainTools.PivotedDomains.Analytics.GoogleAnalyticTrackingCode | Number | Google Analytics Tracking Code | 


##### Command Example
`domaintoolsiris-pivot ip=127.0.0.1`

##### Context Example
```

```

##### Human Readable Output
=======
| DomainTools.PivotedDomains.Name | String | The DomainTools Domain Name. | 
| DomainTools.PivotedDomains.LastEnriched | Date | The last time DomainTools enriched the domain data. | 
| DomainTools.PivotedDomains.Analytics.OverallRiskScore | Number | The DomainTools Overall Risk Score. | 
| DomainTools.PivotedDomains.Analytics.ProximityRiskScore | Number | The DomainTools Proximity Risk Score. | 
| DomainTools.PivotedDomains.Analytics.ThreatProfileRiskScore.RiskScore | Number | The DomainTools Threat Profile Risk Score. | 
| DomainTools.PivotedDomains.Analytics.ThreatProfileRiskScore.Threats | String | The DomainTools Threat Profile Threats. | 
| DomainTools.PivotedDomains.Analytics.ThreatProfileRiskScore.Evidence | String | The DomainTools Threat Profile Evidence. | 
| DomainTools.PivotedDomains.Analytics.WebsiteResponseCode | Number | The response code of the website. | 
| DomainTools.PivotedDomains.Analytics.AlexaRank | Number | The Alexa rank. | 
| DomainTools.PivotedDomains.Analytics.Tags | String | The DomainTools tags. | 
| DomainTools.PivotedDomains.Identity.RegistrantName | String | The name of the registrant. | 
| DomainTools.PivotedDomains.Identity.RegistrantOrg | String | The organization of the registrant. | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Country.value | String | The country value of the registrant contact. | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Country.count | Number | The country count of the registrant contact. | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Email.value | String | The Email value of the registrant contact. | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Email.count | Number | The Email count of the registrant contact. | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Name.value | String | The name value of the registrant contact. | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Name.count | Number | The name count of the registrant contact. | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Phone.value | String | The phone value of of the registrant contact. | 
| DomainTools.PivotedDomains.Identity.RegistrantContact.Phone.count | Number | The phone count of the registrant contact. | 
| DomainTools.PivotedDomains.Identity.SOAEmail | String | The SOA record Email. | 
| DomainTools.PivotedDomains.Identity.SSLCertificateEmail | String | The SSL certificate Email. | 
| DomainTools.PivotedDomains.Identity.AdminContact.Country.value | String | The country value of the administrator contact. | 
| DomainTools.PivotedDomains.Identity.AdminContact.Country.count | Number | The country count of the administrator contact. | 
| DomainTools.PivotedDomains.Identity.AdminContact.Email.value | String | The Email value of the administrator contact. | 
| DomainTools.PivotedDomains.Identity.AdminContact.Email.count | Number | The Email count of the administrator contact. | 
| DomainTools.PivotedDomains.Identity.AdminContact.Name.value | String | The name value of the administrator contact. | 
| DomainTools.PivotedDomains.Identity.AdminContact.Name.count | Number | The name count of the administrator contact. | 
| DomainTools.PivotedDomains.Identity.AdminContact.Phone.value | String | The phone value of the administrator contact. | 
| DomainTools.PivotedDomains.Identity.AdminContact.Phone.count | Number | The phone count of the administrator contact. | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Country.value | String | The country value of the technical contact. | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Country.count | Number | The country count of the technical contact. | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Email.value | String | The Email value of the technical contact. | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Email.count | Number | The Email count of the technical contact. | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Name.value | String | The name value of the technical contact. | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Name.count | Number | The name count of the technical contact. | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Phone.value | String | The phone value of the technical contact. | 
| DomainTools.PivotedDomains.Identity.TechnicalContact.Phone.count | Number | The phone count of the technical contact. | 
| DomainTools.PivotedDomains.Identity.BillingContact.Country.value | String | The country value of the billing contact. | 
| DomainTools.PivotedDomains.Identity.BillingContact.Country.count | Number | The country count of the billing contact. | 
| DomainTools.PivotedDomains.Identity.BillingContact.Email.value | String | The Email value of the billing contact. | 
| DomainTools.PivotedDomains.Identity.BillingContact.Email.count | Number | The Email count of the billing contact. | 
| DomainTools.PivotedDomains.Identity.BillingContact.Name.value | String | The Name value of the billing contact. | 
| DomainTools.PivotedDomains.Identity.BillingContact.Name.count | Number | The Name count of the billing contact. | 
| DomainTools.PivotedDomains.Identity.BillingContact.Phone.value | String | The phone value of the billing contact. | 
| DomainTools.PivotedDomains.Identity.BillingContact.Phone.count | Number | The phone count of the billing contact. | 
| DomainTools.PivotedDomains.Identity.EmailDomains | String | The Email domains. | 
| DomainTools.PivotedDomains.Identity.AdditionalWhoisEmails.value | String | The value of the Additional Whois Emails. | 
| DomainTools.PivotedDomains.Identity.AdditionalWhoisEmails.count | Number | The count of the Additional Whois Emails. | 
| DomainTools.PivotedDomains.Registration.DomainRegistrant | String | The Registrant of the domain. | 
| DomainTools.PivotedDomains.Registration.RegistrarStatus | String | The status of the registrar. | 
| DomainTools.PivotedDomains.Registration.DomainStatus | Boolean | The active status of the registrar. | 
| DomainTools.PivotedDomains.Registration.CreateDate | Date | The date the domain was created. | 
| DomainTools.PivotedDomains.Registration.ExpirationDate | Date | The Expiry date of the domain. | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.address.value | String | The address value of IP addresses. | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.address.count | Number | The address count of IP addresses. | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.asn.value | String | The ASN value of IP addresses. | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.asn.count | Number | The ASN count of IP addresses. | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.country_code.value | String | The country code value of IP addresses. | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.country_code.count | Number | The country code count of IP addresses. | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.isp.value | String | The ISP value of IP addresses. | 
| DomainTools.PivotedDomains.Hosting.IPAddresses.isp.count | Number | The ISP count of IP addresses. | 
| DomainTools.PivotedDomains.Hosting.IPCountryCode | String | The country code of the IP address. | 
| DomainTools.PivotedDomains.Hosting.MailServers.domain.value | String | The domain value of the Mail Servers. | 
| DomainTools.PivotedDomains.Hosting.MailServers.domain.count | Number | The domain count of the Mail Servers. | 
| DomainTools.PivotedDomains.Hosting.MailServers.host.value | String | The host value of the Mail Servers. | 
| DomainTools.PivotedDomains.Hosting.MailServers.host.count | Number | The host count of the Mail Servers. | 
| DomainTools.PivotedDomains.Hosting.MailServers.ip.value | String | The IP address value of the Mail Servers. | 
| DomainTools.PivotedDomains.Hosting.MailServers.ip.count | Number | The IP address count of the Mail Servers. | 
| DomainTools.PivotedDomains.Hosting.SPFRecord | String | The SPF record Information. | 
| DomainTools.PivotedDomains.Hosting.NameServers.domain.value | String | The domain value of DomainTools Domains NameServers. | 
| DomainTools.PivotedDomains.Hosting.NameServers.domain.count | Number | The domain count of DomainTools Domains NameServers. | 
| DomainTools.PivotedDomains.Hosting.NameServers.host.value | String | The host value of DomainTools Domains NameServers. | 
| DomainTools.PivotedDomains.Hosting.NameServers.host.count | Number | The host count of DomainTools Domains NameServers. | 
| DomainTools.PivotedDomains.Hosting.NameServers.ip.value | String | The IP address value of DomainTools Domains NameServers. | 
| DomainTools.PivotedDomains.Hosting.NameServers.ip.count | Number | The IP address count of DomainTools Domains NameServers. | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.hash.value | String | The hash value of the SSL certificate. | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.hash.count | Number | The hash count of the SSL certificate. | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.organization.value | String | The organization value of the SSL certificate. | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.organization.count | Number | The organization count of the SSL certificate. | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.subject.value | String | The subject value of the SSL certificate. | 
| DomainTools.PivotedDomains.Hosting.SSLCertificate.subject.count | Number | The subject count of the SSL certificate. | 
| DomainTools.PivotedDomains.Hosting.RedirectsTo.value | String | The Redirects To value of the domain. | 
| DomainTools.PivotedDomains.Hosting.RedirectsTo.count | Number | The Redirects To count of the domain. | 
| DomainTools.PivotedDomains.Analytics.GoogleAdsenseTrackingCode | Number | The tracking code of Google Adsense. | 
| DomainTools.PivotedDomains.Analytics.GoogleAnalyticTrackingCode | Number | The tracking code Google Analytics. |
