## DomainTools Iris Playbook
---

## Configure DomainTools Iris on Demisto
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for DomainTools Iris.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __API Username__
    * __API Key__
    * __High-Risk Threshold__
    * __Young Domain Timeframe (within Days)__
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.
## Fetched Incidents Data
---

## Commands
---
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. domain
2. domaintoolsiris-analytics
3. domaintoolsiris-threat-profile
4. domaintoolsiris-pivot
### 1. domain
---
Get a complete profile of the domain provided.
##### Base Command

`domain`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | Domain Name | 
| Domain.DNS | String | Domain DNS | 
| Domain.DomainStatus | Boolean | Domain Status | 
| Domain.CreationDate | Date | Domain Creation Date | 
| Domain.ExpirationDate | Date | Domain Expiration Date | 
| Domain.NameServers | String | Domain NameServers | 
| Domain.Registrant.Country | String | Domain Registrant Country | 
| Domain.Registrant.Email | String | Domain Registrant Email | 
| Domain.Registrant.Name | String | Domain Registrant Name | 
| Domain.Registrant.Phone | String | Domain Registrant Phone | 
| Domain.Malicious.Vendor | String | Vendor that saw domain as malicious | 
| Domain.Malicious.Description | String | Description of why domain was found to be malicious | 
| DomainTools.Domains.Name | String | DomainTools Domain Name | 
| DomainTools.Domains.LastEnriched | Date | Last Time DomainTools Enriched Domain Data | 
| DomainTools.Domains.Analytics.OverallRiskScore | Number | DomainTools Overall Risk Score | 
| DomainTools.Domains.Analytics.ProximityRiskScore | Number | DomainTools Proximity Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.RiskScore | Number | DomainTools Threat Profile Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Threats | String | DomainTools Threat Profile Threats | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Evidence | String | DomainTools Threat Profile Evidence | 
| DomainTools.Domains.Analytics.WebsiteResponseCode | Number | Website Response Code | 
| DomainTools.Domains.Analytics.AlexaRank | Number | Alexa Rank | 
| DomainTools.Domains.Analytics.Tags | String | DomainTools Tags | 
| DomainTools.Domains.Identity.RegistrantName | String | Registrant Name | 
| DomainTools.Domains.Identity.RegistrantOrg | String | Registrant Org | 
| DomainTools.Domains.Identity.RegistrantContact.Country.value | String | Registrant Contact Country value | 
| DomainTools.Domains.Identity.RegistrantContact.Country.count | Number | Registrant Contact Country count | 
| DomainTools.Domains.Identity.RegistrantContact.Email.value | String | Registrant Contact Email value | 
| DomainTools.Domains.Identity.RegistrantContact.Email.count | Number | Registrant Contact Email count | 
| DomainTools.Domains.Identity.RegistrantContact.Name.value | String | Registrant Contact Name value | 
| DomainTools.Domains.Identity.RegistrantContact.Name.count | Number | Registrant Contact Name count | 
| DomainTools.Domains.Identity.RegistrantContact.Phone.value | String | Registrant Contact Phone value | 
| DomainTools.Domains.Identity.RegistrantContact.Phone.count | Number | Registrant Contact Phone count | 
| DomainTools.Domains.Identity.SOAEmail | String | SOA Record Email | 
| DomainTools.Domains.Identity.SSLCertificateEmail | String | SSL Certificate Email | 
| DomainTools.Domains.Identity.AdminContact.Country.value | String | Admin Contact Country value | 
| DomainTools.Domains.Identity.AdminContact.Country.count | Number | Admin Contact Country count | 
| DomainTools.Domains.Identity.AdminContact.Email.value | String | Admin Contact Email value | 
| DomainTools.Domains.Identity.AdminContact.Email.count | Number | Admin Contact Email count | 
| DomainTools.Domains.Identity.AdminContact.Name.value | String | Admin Contact Name value | 
| DomainTools.Domains.Identity.AdminContact.Name.count | Number | Admin Contact Name count | 
| DomainTools.Domains.Identity.AdminContact.Phone.value | String | Admin Contact Phone value | 
| DomainTools.Domains.Identity.AdminContact.Phone.count | Number | Admin Contact Phone count | 
| DomainTools.Domains.Identity.TechnicalContact.Country.value | String | Technical Contact Country value | 
| DomainTools.Domains.Identity.TechnicalContact.Country.count | Number | Technical Contact Country count | 
| DomainTools.Domains.Identity.TechnicalContact.Email.value | String | Technical Contact Email value | 
| DomainTools.Domains.Identity.TechnicalContact.Email.count | Number | Technical Contact Email count | 
| DomainTools.Domains.Identity.TechnicalContact.Name.value | String | Technical Contact Name value | 
| DomainTools.Domains.Identity.TechnicalContact.Name.count | Number | Technical Contact Name count | 
| DomainTools.Domains.Identity.TechnicalContact.Phone.value | String | Technical Contact Phone value | 
| DomainTools.Domains.Identity.TechnicalContact.Phone.count | Number | Technical Contact Phone count | 
| DomainTools.Domains.Identity.BillingContact.Country.value | String | Billing Contact Country value | 
| DomainTools.Domains.Identity.BillingContact.Country.count | Number | Billing Contact Country count | 
| DomainTools.Domains.Identity.BillingContact.Email.value | String | Billing Contact Email value | 
| DomainTools.Domains.Identity.BillingContact.Email.count | Number | Billing Contact Email count | 
| DomainTools.Domains.Identity.BillingContact.Name.value | String | Billing Contact Name value | 
| DomainTools.Domains.Identity.BillingContact.Name.count | Number | Billing Contact Name count | 
| DomainTools.Domains.Identity.BillingContact.Phone.value | String | Billing Contact Phone value | 
| DomainTools.Domains.Identity.BillingContact.Phone.count | Number | Billing Contact Phone count | 
| DomainTools.Domains.Identity.EmailDomains | String | Email Domains | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails.value | String | Additional Whois Emails value | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails.count | Number | Additional Whois Emails count | 
| DomainTools.Domains.Registration.DomainRegistrant | String | Domain Registrant | 
| DomainTools.Domains.Registration.RegistrarStatus | String | Registrar Status | 
| DomainTools.Domains.Registration.DomainStatus | Boolean | Domain Active Status | 
| DomainTools.Domains.Registration.CreateDate | Date | Create Date | 
| DomainTools.Domains.Registration.ExpirationDate | Date | Expiration Date | 
| DomainTools.Domains.Hosting.IPAddresses.address.value | String | IP Addresses Info address value | 
| DomainTools.Domains.Hosting.IPAddresses.address.count | Number | IP Addresses Info address count | 
| DomainTools.Domains.Hosting.IPAddresses.asn.value | String | IP Addresses Info asn value | 
| DomainTools.Domains.Hosting.IPAddresses.asn.count | Number | IP Addresses Info asn count | 
| DomainTools.Domains.Hosting.IPAddresses.country_code.value | String | IP Addresses Info country_code value | 
| DomainTools.Domains.Hosting.IPAddresses.country_code.count | Number | IP Addresses Info country_code count | 
| DomainTools.Domains.Hosting.IPAddresses.isp.value | String | IP Addresses Info isp value | 
| DomainTools.Domains.Hosting.IPAddresses.isp.count | Number | IP Addresses Info isp count | 
| DomainTools.Domains.Hosting.IPCountryCode | String | IP Country Code | 
| DomainTools.Domains.Hosting.MailServers.domain.value | String | Mail Servers Info domain value | 
| DomainTools.Domains.Hosting.MailServers.domain.count | Number | Mail Servers Info domain count | 
| DomainTools.Domains.Hosting.MailServers.host.value | String | Mail Servers Info host value | 
| DomainTools.Domains.Hosting.MailServers.host.count | Number | Mail Servers Info host count | 
| DomainTools.Domains.Hosting.MailServers.ip.value | String | Mail Servers Info ip value | 
| DomainTools.Domains.Hosting.MailServers.ip.count | Number | Mail Servers Info ip count | 
| DomainTools.Domains.Hosting.SPFRecord | String | SPF Record Info | 
| DomainTools.Domains.Hosting.NameServers.domain.value | String | DomainTools Domains NameServers domain value | 
| DomainTools.Domains.Hosting.NameServers.domain.count | Number | DomainTools Domains NameServers domain count | 
| DomainTools.Domains.Hosting.NameServers.host.value | String | DomainTools Domains NameServers host value | 
| DomainTools.Domains.Hosting.NameServers.host.count | Number | DomainTools Domains NameServers host count | 
| DomainTools.Domains.Hosting.NameServers.ip.value | String | DomainTools Domains NameServers ip value | 
| DomainTools.Domains.Hosting.NameServers.ip.count | Number | DomainTools Domains NameServers ip count | 
| DomainTools.Domains.Hosting.SSLCertificate.hash.value | String | SSL Certificate Info hash value | 
| DomainTools.Domains.Hosting.SSLCertificate.hash.count | Number | SSL Certificate Info hash count | 
| DomainTools.Domains.Hosting.SSLCertificate.organization.value | String | SSL Certificate Info organization value | 
| DomainTools.Domains.Hosting.SSLCertificate.organization.count | Number | SSL Certificate Info organization count | 
| DomainTools.Domains.Hosting.SSLCertificate.subject.value | String | SSL Certificate Info subject value | 
| DomainTools.Domains.Hosting.SSLCertificate.subject.count | Number | SSL Certificate Info subject count | 
| DomainTools.Domains.Hosting.RedirectsTo.value | String | Domains it Redirects To value | 
| DomainTools.Domains.Hosting.RedirectsTo.count | Number | Domains it Redirects To count | 
| DomainTools.Domains.Analytics.GoogleAdsenseTrackingCode | Number | Google Adsense Tracking Code | 
| DomainTools.Domains.Analytics.GoogleAnalyticTrackingCode | Number | Google Analytics Tracking Code | 
| DBotScore.Indicator | String | DBotScore Indicator | 
| DBotScore.Type | String | DBotScore Indicator Type | 
| DBotScore.Vendor | String | Vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 


##### Command Example
`!domain domain=demisto.com`

##### Context Example
```

```

##### Human Readable Output


### 2. domaintoolsiris-analytics
---
Provides markdown table with DomainTools Analytic data
##### Base Command

`domaintoolsiris-analytics`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | Domain Name | 
| Domain.DNS | String | Domain DNS | 
| Domain.DomainStatus | Boolean | Domain Status | 
| Domain.CreationDate | Date | Domain Creation Date | 
| Domain.ExpirationDate | Date | Domain Expiration Date | 
| Domain.NameServers | String | Domain NameServers | 
| Domain.Registrant.Country | String | Domain Registrant Country | 
| Domain.Registrant.Email | String | Domain Registrant Email | 
| Domain.Registrant.Name | String | Domain Registrant Name | 
| Domain.Registrant.Phone | String | Domain Registrant Phone | 
| Domain.Malicious.Vendor | String | Vendor that saw domain as malicious | 
| Domain.Malicious.Description | String | Description of why domain was found to be malicious | 
| DomainTools.Domains.Name | String | DomainTools Domain Name | 
| DomainTools.Domains.LastEnriched | Date | Last Time DomainTools Enriched Domain Data | 
| DomainTools.Domains.Analytics.OverallRiskScore | Number | DomainTools Overall Risk Score | 
| DomainTools.Domains.Analytics.ProximityRiskScore | Number | DomainTools Proximity Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.RiskScore | Number | DomainTools Threat Profile Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Threats | String | DomainTools Threat Profile Threats | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Evidence | String | DomainTools Threat Profile Evidence | 
| DomainTools.Domains.Analytics.WebsiteResponseCode | Number | Website Response Code | 
| DomainTools.Domains.Analytics.AlexaRank | Number | Alexa Rank | 
| DomainTools.Domains.Analytics.Tags | String | DomainTools Tags | 
| DomainTools.Domains.Identity.RegistrantName | String | Registrant Name | 
| DomainTools.Domains.Identity.RegistrantOrg | String | Registrant Org | 
| DomainTools.Domains.Identity.RegistrantContact.Country.value | String | Registrant Contact Country value | 
| DomainTools.Domains.Identity.RegistrantContact.Country.count | Number | Registrant Contact Country count | 
| DomainTools.Domains.Identity.RegistrantContact.Email.value | String | Registrant Contact Email value | 
| DomainTools.Domains.Identity.RegistrantContact.Email.count | Number | Registrant Contact Email count | 
| DomainTools.Domains.Identity.RegistrantContact.Name.value | String | Registrant Contact Name value | 
| DomainTools.Domains.Identity.RegistrantContact.Name.count | Number | Registrant Contact Name count | 
| DomainTools.Domains.Identity.RegistrantContact.Phone.value | String | Registrant Contact Phone value | 
| DomainTools.Domains.Identity.RegistrantContact.Phone.count | Number | Registrant Contact Phone count | 
| DomainTools.Domains.Identity.SOAEmail | String | SOA Record Email | 
| DomainTools.Domains.Identity.SSLCertificateEmail | String | SSL Certificate Email | 
| DomainTools.Domains.Identity.AdminContact.Country.value | String | Admin Contact Country value | 
| DomainTools.Domains.Identity.AdminContact.Country.count | Number | Admin Contact Country count | 
| DomainTools.Domains.Identity.AdminContact.Email.value | String | Admin Contact Email value | 
| DomainTools.Domains.Identity.AdminContact.Email.count | Number | Admin Contact Email count | 
| DomainTools.Domains.Identity.AdminContact.Name.value | String | Admin Contact Name value | 
| DomainTools.Domains.Identity.AdminContact.Name.count | Number | Admin Contact Name count | 
| DomainTools.Domains.Identity.AdminContact.Phone.value | String | Admin Contact Phone value | 
| DomainTools.Domains.Identity.AdminContact.Phone.count | Number | Admin Contact Phone count | 
| DomainTools.Domains.Identity.TechnicalContact.Country.value | String | Technical Contact Country value | 
| DomainTools.Domains.Identity.TechnicalContact.Country.count | Number | Technical Contact Country count | 
| DomainTools.Domains.Identity.TechnicalContact.Email.value | String | Technical Contact Email value | 
| DomainTools.Domains.Identity.TechnicalContact.Email.count | Number | Technical Contact Email count | 
| DomainTools.Domains.Identity.TechnicalContact.Name.value | String | Technical Contact Name value | 
| DomainTools.Domains.Identity.TechnicalContact.Name.count | Number | Technical Contact Name count | 
| DomainTools.Domains.Identity.TechnicalContact.Phone.value | String | Technical Contact Phone value | 
| DomainTools.Domains.Identity.TechnicalContact.Phone.count | Number | Technical Contact Phone count | 
| DomainTools.Domains.Identity.BillingContact.Country.value | String | Billing Contact Country value | 
| DomainTools.Domains.Identity.BillingContact.Country.count | Number | Billing Contact Country count | 
| DomainTools.Domains.Identity.BillingContact.Email.value | String | Billing Contact Email value | 
| DomainTools.Domains.Identity.BillingContact.Email.count | Number | Billing Contact Email count | 
| DomainTools.Domains.Identity.BillingContact.Name.value | String | Billing Contact Name value | 
| DomainTools.Domains.Identity.BillingContact.Name.count | Number | Billing Contact Name count | 
| DomainTools.Domains.Identity.BillingContact.Phone.value | String | Billing Contact Phone value | 
| DomainTools.Domains.Identity.BillingContact.Phone.count | Number | Billing Contact Phone count | 
| DomainTools.Domains.Identity.EmailDomains | String | Email Domains | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails.value | String | Additional Whois Emails value | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails.count | Number | Additional Whois Emails count | 
| DomainTools.Domains.Registration.DomainRegistrant | String | Domain Registrant | 
| DomainTools.Domains.Registration.RegistrarStatus | String | Registrar Status | 
| DomainTools.Domains.Registration.DomainStatus | Boolean | Domain Active Status | 
| DomainTools.Domains.Registration.CreateDate | Date | Create Date | 
| DomainTools.Domains.Registration.ExpirationDate | Date | Expiration Date | 
| DomainTools.Domains.Hosting.IPAddresses.address.value | String | IP Addresses Info address value | 
| DomainTools.Domains.Hosting.IPAddresses.address.count | Number | IP Addresses Info address count | 
| DomainTools.Domains.Hosting.IPAddresses.asn.value | String | IP Addresses Info asn value | 
| DomainTools.Domains.Hosting.IPAddresses.asn.count | Number | IP Addresses Info asn count | 
| DomainTools.Domains.Hosting.IPAddresses.country_code.value | String | IP Addresses Info country_code value | 
| DomainTools.Domains.Hosting.IPAddresses.country_code.count | Number | IP Addresses Info country_code count | 
| DomainTools.Domains.Hosting.IPAddresses.isp.value | String | IP Addresses Info isp value | 
| DomainTools.Domains.Hosting.IPAddresses.isp.count | Number | IP Addresses Info isp count | 
| DomainTools.Domains.Hosting.IPCountryCode | String | IP Country Code | 
| DomainTools.Domains.Hosting.MailServers.domain.value | String | Mail Servers Info domain value | 
| DomainTools.Domains.Hosting.MailServers.domain.count | Number | Mail Servers Info domain count | 
| DomainTools.Domains.Hosting.MailServers.host.value | String | Mail Servers Info host value | 
| DomainTools.Domains.Hosting.MailServers.host.count | Number | Mail Servers Info host count | 
| DomainTools.Domains.Hosting.MailServers.ip.value | String | Mail Servers Info ip value | 
| DomainTools.Domains.Hosting.MailServers.ip.count | Number | Mail Servers Info ip count | 
| DomainTools.Domains.Hosting.SPFRecord | String | SPF Record Info | 
| DomainTools.Domains.Hosting.NameServers.domain.value | String | DomainTools Domains NameServers domain value | 
| DomainTools.Domains.Hosting.NameServers.domain.count | Number | DomainTools Domains NameServers domain count | 
| DomainTools.Domains.Hosting.NameServers.host.value | String | DomainTools Domains NameServers host value | 
| DomainTools.Domains.Hosting.NameServers.host.count | Number | DomainTools Domains NameServers host count | 
| DomainTools.Domains.Hosting.NameServers.ip.value | String | DomainTools Domains NameServers ip value | 
| DomainTools.Domains.Hosting.NameServers.ip.count | Number | DomainTools Domains NameServers ip count | 
| DomainTools.Domains.Hosting.SSLCertificate.hash.value | String | SSL Certificate Info hash value | 
| DomainTools.Domains.Hosting.SSLCertificate.hash.count | Number | SSL Certificate Info hash count | 
| DomainTools.Domains.Hosting.SSLCertificate.organization.value | String | SSL Certificate Info organization value | 
| DomainTools.Domains.Hosting.SSLCertificate.organization.count | Number | SSL Certificate Info organization count | 
| DomainTools.Domains.Hosting.SSLCertificate.subject.value | String | SSL Certificate Info subject value | 
| DomainTools.Domains.Hosting.SSLCertificate.subject.count | Number | SSL Certificate Info subject count | 
| DomainTools.Domains.Hosting.RedirectsTo.value | String | Domains it Redirects To value | 
| DomainTools.Domains.Hosting.RedirectsTo.count | Number | Domains it Redirects To count | 
| DomainTools.Domains.Analytics.GoogleAdsenseTrackingCode | Number | Google Adsense Tracking Code | 
| DomainTools.Domains.Analytics.GoogleAnalyticTrackingCode | Number | Google Analytics Tracking Code | 
| DBotScore.Indicator | String | DBotScore Indicator | 
| DBotScore.Type | String | DBotScore Indicator Type | 
| DBotScore.Vendor | String | Vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 


##### Command Example
`!domaintoolsiris-analytics domain=demisto.com`

##### Context Example
```

```

##### Human Readable Output


### 3. domaintoolsiris-threat-profile
---
Provides markdown table with DomainTools Threat Profile data
##### Base Command

`domaintoolsiris-threat-profile`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain name | Required | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Domain.Name | String | Domain Name | 
| Domain.DNS | String | Domain DNS | 
| Domain.DomainStatus | Boolean | Domain Status | 
| Domain.CreationDate | Date | Domain Creation Date | 
| Domain.ExpirationDate | Date | Domain Expiration Date | 
| Domain.NameServers | String | Domain NameServers | 
| Domain.Registrant.Country | String | Domain Registrant Country | 
| Domain.Registrant.Email | String | Domain Registrant Email | 
| Domain.Registrant.Name | String | Domain Registrant Name | 
| Domain.Registrant.Phone | String | Domain Registrant Phone | 
| Domain.Malicious.Vendor | String | Vendor that saw domain as malicious | 
| Domain.Malicious.Description | String | Description of why domain was found to be malicious | 
| DomainTools.Domains.Name | String | DomainTools Domain Name | 
| DomainTools.Domains.LastEnriched | Date | Last Time DomainTools Enriched Domain Data | 
| DomainTools.Domains.Analytics.OverallRiskScore | Number | DomainTools Overall Risk Score | 
| DomainTools.Domains.Analytics.ProximityRiskScore | Number | DomainTools Proximity Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.RiskScore | Number | DomainTools Threat Profile Risk Score | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Threats | String | DomainTools Threat Profile Threats | 
| DomainTools.Domains.Analytics.ThreatProfileRiskScore.Evidence | String | DomainTools Threat Profile Evidence | 
| DomainTools.Domains.Analytics.WebsiteResponseCode | Number | Website Response Code | 
| DomainTools.Domains.Analytics.AlexaRank | Number | Alexa Rank | 
| DomainTools.Domains.Analytics.Tags | String | DomainTools Tags | 
| DomainTools.Domains.Identity.RegistrantName | String | Registrant Name | 
| DomainTools.Domains.Identity.RegistrantOrg | String | Registrant Org | 
| DomainTools.Domains.Identity.RegistrantContact.Country.value | String | Registrant Contact Country value | 
| DomainTools.Domains.Identity.RegistrantContact.Country.count | Number | Registrant Contact Country count | 
| DomainTools.Domains.Identity.RegistrantContact.Email.value | String | Registrant Contact Email value | 
| DomainTools.Domains.Identity.RegistrantContact.Email.count | Number | Registrant Contact Email count | 
| DomainTools.Domains.Identity.RegistrantContact.Name.value | String | Registrant Contact Name value | 
| DomainTools.Domains.Identity.RegistrantContact.Name.count | Number | Registrant Contact Name count | 
| DomainTools.Domains.Identity.RegistrantContact.Phone.value | String | Registrant Contact Phone value | 
| DomainTools.Domains.Identity.RegistrantContact.Phone.count | Number | Registrant Contact Phone count | 
| DomainTools.Domains.Identity.SOAEmail | String | SOA Record Email | 
| DomainTools.Domains.Identity.SSLCertificateEmail | String | SSL Certificate Email | 
| DomainTools.Domains.Identity.AdminContact.Country.value | String | Admin Contact Country value | 
| DomainTools.Domains.Identity.AdminContact.Country.count | Number | Admin Contact Country count | 
| DomainTools.Domains.Identity.AdminContact.Email.value | String | Admin Contact Email value | 
| DomainTools.Domains.Identity.AdminContact.Email.count | Number | Admin Contact Email count | 
| DomainTools.Domains.Identity.AdminContact.Name.value | String | Admin Contact Name value | 
| DomainTools.Domains.Identity.AdminContact.Name.count | Number | Admin Contact Name count | 
| DomainTools.Domains.Identity.AdminContact.Phone.value | String | Admin Contact Phone value | 
| DomainTools.Domains.Identity.AdminContact.Phone.count | Number | Admin Contact Phone count | 
| DomainTools.Domains.Identity.TechnicalContact.Country.value | String | Technical Contact Country value | 
| DomainTools.Domains.Identity.TechnicalContact.Country.count | Number | Technical Contact Country count | 
| DomainTools.Domains.Identity.TechnicalContact.Email.value | String | Technical Contact Email value | 
| DomainTools.Domains.Identity.TechnicalContact.Email.count | Number | Technical Contact Email count | 
| DomainTools.Domains.Identity.TechnicalContact.Name.value | String | Technical Contact Name value | 
| DomainTools.Domains.Identity.TechnicalContact.Name.count | Number | Technical Contact Name count | 
| DomainTools.Domains.Identity.TechnicalContact.Phone.value | String | Technical Contact Phone value | 
| DomainTools.Domains.Identity.TechnicalContact.Phone.count | Number | Technical Contact Phone count | 
| DomainTools.Domains.Identity.BillingContact.Country.value | String | Billing Contact Country value | 
| DomainTools.Domains.Identity.BillingContact.Country.count | Number | Billing Contact Country count | 
| DomainTools.Domains.Identity.BillingContact.Email.value | String | Billing Contact Email value | 
| DomainTools.Domains.Identity.BillingContact.Email.count | Number | Billing Contact Email count | 
| DomainTools.Domains.Identity.BillingContact.Name.value | String | Billing Contact Name value | 
| DomainTools.Domains.Identity.BillingContact.Name.count | Number | Billing Contact Name count | 
| DomainTools.Domains.Identity.BillingContact.Phone.value | String | Billing Contact Phone value | 
| DomainTools.Domains.Identity.BillingContact.Phone.count | Number | Billing Contact Phone count | 
| DomainTools.Domains.Identity.EmailDomains | String | Email Domains | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails.value | String | Additional Whois Emails value | 
| DomainTools.Domains.Identity.AdditionalWhoisEmails.count | Number | Additional Whois Emails count | 
| DomainTools.Domains.Registration.DomainRegistrant | String | Domain Registrant | 
| DomainTools.Domains.Registration.RegistrarStatus | String | Registrar Status | 
| DomainTools.Domains.Registration.DomainStatus | Boolean | Domain Active Status | 
| DomainTools.Domains.Registration.CreateDate | Date | Create Date | 
| DomainTools.Domains.Registration.ExpirationDate | Date | Expiration Date | 
| DomainTools.Domains.Hosting.IPAddresses.address.value | String | IP Addresses Info address value | 
| DomainTools.Domains.Hosting.IPAddresses.address.count | Number | IP Addresses Info address count | 
| DomainTools.Domains.Hosting.IPAddresses.asn.value | String | IP Addresses Info asn value | 
| DomainTools.Domains.Hosting.IPAddresses.asn.count | Number | IP Addresses Info asn count | 
| DomainTools.Domains.Hosting.IPAddresses.country_code.value | String | IP Addresses Info country_code value | 
| DomainTools.Domains.Hosting.IPAddresses.country_code.count | Number | IP Addresses Info country_code count | 
| DomainTools.Domains.Hosting.IPAddresses.isp.value | String | IP Addresses Info isp value | 
| DomainTools.Domains.Hosting.IPAddresses.isp.count | Number | IP Addresses Info isp count | 
| DomainTools.Domains.Hosting.IPCountryCode | String | IP Country Code | 
| DomainTools.Domains.Hosting.MailServers.domain.value | String | Mail Servers Info domain value | 
| DomainTools.Domains.Hosting.MailServers.domain.count | Number | Mail Servers Info domain count | 
| DomainTools.Domains.Hosting.MailServers.host.value | String | Mail Servers Info host value | 
| DomainTools.Domains.Hosting.MailServers.host.count | Number | Mail Servers Info host count | 
| DomainTools.Domains.Hosting.MailServers.ip.value | String | Mail Servers Info ip value | 
| DomainTools.Domains.Hosting.MailServers.ip.count | Number | Mail Servers Info ip count | 
| DomainTools.Domains.Hosting.SPFRecord | String | SPF Record Info | 
| DomainTools.Domains.Hosting.NameServers.domain.value | String | DomainTools Domains NameServers domain value | 
| DomainTools.Domains.Hosting.NameServers.domain.count | Number | DomainTools Domains NameServers domain count | 
| DomainTools.Domains.Hosting.NameServers.host.value | String | DomainTools Domains NameServers host value | 
| DomainTools.Domains.Hosting.NameServers.host.count | Number | DomainTools Domains NameServers host count | 
| DomainTools.Domains.Hosting.NameServers.ip.value | String | DomainTools Domains NameServers ip value | 
| DomainTools.Domains.Hosting.NameServers.ip.count | Number | DomainTools Domains NameServers ip count | 
| DomainTools.Domains.Hosting.SSLCertificate.hash.value | String | SSL Certificate Info hash value | 
| DomainTools.Domains.Hosting.SSLCertificate.hash.count | Number | SSL Certificate Info hash count | 
| DomainTools.Domains.Hosting.SSLCertificate.organization.value | String | SSL Certificate Info organization value | 
| DomainTools.Domains.Hosting.SSLCertificate.organization.count | Number | SSL Certificate Info organization count | 
| DomainTools.Domains.Hosting.SSLCertificate.subject.value | String | SSL Certificate Info subject value | 
| DomainTools.Domains.Hosting.SSLCertificate.subject.count | Number | SSL Certificate Info subject count | 
| DomainTools.Domains.Hosting.RedirectsTo.value | String | Domains it Redirects To value | 
| DomainTools.Domains.Hosting.RedirectsTo.count | Number | Domains it Redirects To count | 
| DomainTools.Domains.Analytics.GoogleAdsenseTrackingCode | Number | Google Adsense Tracking Code | 
| DomainTools.Domains.Analytics.GoogleAnalyticTrackingCode | Number | Google Analytics Tracking Code | 
| DBotScore.Indicator | String | DBotScore Indicator | 
| DBotScore.Type | String | DBotScore Indicator Type | 
| DBotScore.Vendor | String | Vendor used to calculate the score | 
| DBotScore.Score | Number | The actual score | 


##### Command Example
`!domaintoolsiris-threat-profile domain=demisto.com`

##### Context Example
```

```

##### Human Readable Output


### 4. domaintoolsiris-pivot
---
Using one of the arguements allows a user to get back data on domains related to IPs, Email Addresses, etc.
##### Base Command

`domaintoolsiris-pivot`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP Address | Optional | 
| email | E-mail Address | Optional | 
| nameserver_ip | Name Server IP Address | Optional | 
| ssl_hash | SSL Hash | Optional | 
| nameserver_host | Fully-qualified host name of the name server (ns1.domaintools.net) | Optional | 
| mailserver_host | Fully-qualified host name of the mail server (mx.domaintools.net) | Optional | 


##### Context Output

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
