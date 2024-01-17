Checks for guided pivots for a given domain.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | DomainTools |

## Used In

---
This script is used in the following playbooks and scripts.

* DomainTools Auto Pivots

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| domaintools_data | DomainTools context data for a domain |
| max_registrant_contact_name_count | Max threshold count that can be pivoted to a registrant contact name |
| max_registrant_org_count | Max threshold count that can be pivoted to a registrant org name |
| max_registrar_count | Max threshold count that can be pivoted to a registrar |
| max_ssl_info_organization_count | Max threshold count that can be pivoted to a ssl organization |
| max_ssl_info_hash_count | Max threshold count that can be pivoted to a ssl hash |
| max_ssl_email_count | Max threshold count that can be pivoted to a ssl email |
| max_ssl_subject_count | Max threshold count that can be pivoted to a ssl subject |
| max_name_server_host_count | Max threshold count that can be pivoted to a ssl subject |
| max_name_server_ip_count | Max threshold count that can be pivoted to a nameserver ip |
| max_name_server_domain_count | Max threshold count that can be pivoted to a nameserver domain |
| max_soa_email_count | Max threshold count that can be pivoted to a soa email |
| max_ip_address_count | Max threshold count that can be pivoted to an IP address |
| max_mx_ip_count | Max threshold count that can be pivoted to a MX IP |
| max_mx_host_count | Max threshold count that can be pivoted to a MX Host |
| max_mx_domain_count | Max threshold count that can be pivoted to a MX Domain |
| max_google_adsense_count | Max threshold count that can be pivoted to a google adsense |
| max_google_analytics_count | Max threshold count that can be pivoted to a google analytics |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PivotableDomains.PivotableRegistrantContactName.pivotable | Is the domain's registrant contact name a guided pivot. | Unknown |
| PivotableDomains.PivotableRegistrantContactName.items.count | Number of connected domains sharing the same registrant contact name. | Unknown |
| PivotableDomains.PivotableRegistrantContactName.items.value | Registrant contact name. | Unknown |
| PivotableDomains.PivotableRegistrantOrg.pivotable | Is the domain's registrant org a guided pivot. | Unknown |
| PivotableDomains.PivotableRegistrantOrg.items.count | Number of connected domains sharing the same registrant org. | Unknown |
| PivotableDomains.PivotableRegistrantOrg.items.value | Registrant org. | Unknown |
| PivotableDomains.PivotableSslInfoOrganization.pivotable | Is the domain's ssl org a guided pivot. | Unknown |
| PivotableDomains.PivotableSslInfoOrganization.items.count | Number of connected domains sharing the same ssl org. | Unknown |
| PivotableDomains.PivotableSslInfoOrganization.items.value | SSL org. | Unknown |
| PivotableDomains.PivotableSslInfoHash.pivotable | Is the domain's ssl hash a guided pivot. | Unknown |
| PivotableDomains.PivotableSslInfoHash.items.count | Number of connected domains sharing the same ssl hash. | Unknown |
| PivotableDomains.PivotableSslInfoHash.items.value | SSL hash. | Unknown |
| PivotableDomains.PivotableNameServerHost.pivotable | Is the domain's name server host a guided pivot. | Unknown |
| PivotableDomains.PivotableNameServerHost.items.count | Number of connected domains sharing the same name server host. | Unknown |
| PivotableDomains.PivotableNameServerHost.items.value | name server host. | Unknown |
| PivotableDomains.PivotableSoaEmail.pivotable | Is the domain's name soa email a guided pivot. | Unknown |
| PivotableDomains.PivotableSoaEmail.items.count | Number of connected domains sharing the same name soa email. | Unknown |
| PivotableDomains.PivotableSoaEmail.items.value | soa email. | Unknown |
| PivotableDomains.PivotableIpAddress.pivotable | Is the domain's IP address a guided pivot. | Unknown |
| PivotableDomains.PivotableIpAddress.items.count | Number of connected domains sharing the same IP address. | Unknown |
| PivotableDomains.PivotableIpAddress.items.value | IP address. | Unknown |
| PivotableDomains.PivotableNameServerIp.pivotable | Is the domain's name server IP address a guided pivot. | Unknown |
| PivotableDomains.PivotableNameServerIp.items.count | Number of connected domains sharing the same name server IP address. | Unknown |
| PivotableDomains.PivotableNameServerIp.items.value | name server IP address. | Unknown |
| PivotableDomains.PivotableMxIp.pivotable | Is the domain's mx IP address a guided pivot. | Unknown |
| PivotableDomains.PivotableMxIp.items.count | Number of connected domains sharing the same mx IP address. | Unknown |
| PivotableDomains.PivotableMxIp.items.value | mx IP address. | Unknown |
| PivotableDomains.PivotableRegistrar.pivotable | Is the domain's registrar a guided pivot. | Unknown |
| PivotableDomains.PivotableRegistrar.items.count | Number of connected domains sharing the same registrar. | Unknown |
| PivotableDomains.PivotableRegistrar.items.value | Registrar. | Unknown |
| PivotableDomains.PivotableSslSubject.pivotable | Is the domain's SSL subject a guided pivot. | Unknown |
| PivotableDomains.PivotableSslSubject.items.count | Number of connected domains sharing the SSL subject. | Unknown |
| PivotableDomains.PivotableSslSubject.items.value | SSL subject. | Unknown |
| PivotableDomains.PivotableSslEmail.pivotable | Is the domain's SSL email a guided pivot. | Unknown |
| PivotableDomains.PivotableSslEmail.items.count | Number of connected domains sharing the SSL email. | Unknown |
| PivotableDomains.PivotableSslEmail.items.value | SSL email. | Unknown |
| PivotableDomains.PivotableNameServerDomain.pivotable | Is the domain's name server domain a guided pivot. | Unknown |
| PivotableDomains.PivotableNameServerDomain.items.count | Number of connected domains sharing the name server domain. | Unknown |
| PivotableDomains.PivotableNameServerDomain.items.value | Name server domain. | Unknown |
| PivotableDomains.PivotableMxHost.pivotable | Is the domain's mx host a guided pivot. | Unknown |
| PivotableDomains.PivotableMxHost.items.count | Number of connected domains sharing the mx host. | Unknown |
| PivotableDomains.PivotableMxHost.items.value | MX host. | Unknown |
| PivotableDomains.PivotableMxDomain.pivotable | Is the domain's mx domain a guided pivot. | Unknown |
| PivotableDomains.PivotableMxDomain.items.count | Number of connected domains sharing the mx domain. | Unknown |
| PivotableDomains.PivotableMxDomain.items.value | MX domain. | Unknown |
| PivotableDomains.PivotableGoogleAnalytics.pivotable | Is the domain's Google analytics a guided pivot. | Unknown |
| PivotableDomains.PivotableGoogleAnalytics.items.count | Number of connected domains sharing the Google analytics. | Unknown |
| PivotableDomains.PivotableGoogleAnalytics.items.value | Google analytics. | Unknown |
| PivotableDomains.PivotableAdsense.pivotable | Is the domain's adsense a guided pivot. | Unknown |
| PivotableDomains.PivotableAdsense.items.count | Number of connected domains sharing the adsense. | Unknown |
| PivotableDomains.PivotableAdsense.items.value | Adsense. | Unknown |
