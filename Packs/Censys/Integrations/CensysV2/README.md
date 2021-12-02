Censys is a search engine that allows computer scientists to ask questions about the devices and networks that compose the Internet. Driven by Internet-wide scanning, Censys lets researchers find specific hosts and create aggregate reports on how devices, websites, and certificates are configured and deployed.
This integration was integrated and tested with version xx of CensysV2

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#breaking-changes-from-the-previous-version-of-this-integration-censysv2).

## Configure CensysV2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for CensysV2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | App ID | True |
    | Password | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### censys-host-view
***
Returns host information for the specified IP address.


#### Base Command

`censys-host-view`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The IP Address of the requested host. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Censys.HostView.autonomous_system.asn | Number | The autonomous system number \(ASN\) that the host is in. | 
| Censys.HostView.autonomous_system.bgp_prefix | String | The autonomous system's CIDR. | 
| Censys.HostView.autonomous_system.country_code | String | The autonomous system's two-letter, ISO 3166-1 alpha-2 country code \(e.g., US, CN, GB, RU\). | 
| Censys.HostView.autonomous_system.description | String | A brief description of the autonomous system. | 
| Censys.HostView.autonomous_system.name | String | The friendly name of the autonomous system. | 
| Censys.HostView.autonomous_system_updated_at | Date | When the autonomous system was updated. | 
| Censys.HostView.location.continent | String | The continent of the host's detected location \(e.g., North America, Europe, Asia, South America, Africa, Oceania\). | 
| Censys.HostView.location.coordinates | Unknown | The estimated coordinates of the host's detected location | 
| Censys.HostView.location.country | String | The name of the country of the host's detected location. | 
| Censys.HostView.location.country_code | String | The two-letter ISO 3166-1 alpha-2 country code of the host's detected location \(e.g., US, CN, GB, RU\). | 
| Censys.HostView.location.postal_code | String | The postal code \(if applicable\) of the host's detected location. | 
| Censys.HostView.location.registered_country | String | The name of the host's registered country. | 
| Censys.HostView.location.registered_country_code | String | The registered country's two-letter, ISO 3166-1 alpha-2 country code \(e.g., US, CN, GB, RU\). | 
| Censys.HostView.location.timezone | String | The IANA time zone database name of the host's detected location. | 
| Censys.HostView.services.port | Number | The port the service was reached at. | 
| Censys.HostView.services.observed_at | Date | The UTC timestamp of when Censys scanned the service. | 
| Censys.HostView.services.source_ip | String | The IP address from which Censys scanned the service. | 
| Censys.HostView.services.transport_protocol | String | The transport protocol \(known in OSI model as L4\) used to contact this service \(i.e., UDP or TCP\). | 
| Censys.HostView.services.service_name | String | The name of the service on the port. This is typically the L7 protocol \(e.g., “HTTP”\); however, in the case that a more specific HTTP-based protocol is found \(e.g., Kubernetes or Prometheus\), the field will show that. This field indicates where protocol-specific data will be located. | 
| Censys.HostView.services.extended_service_name | String | The service name with the TLS encryption indicator if the service is using it. For example, "SMTP" will have an extended_serivce_name of "SMTPS" if it's running over tls. | 
| Censys.HostView.services.perspective_id | String | The upstream Internet service provider Censys peered with to scan the service: NTT Communications, TATA, Telia Carrier, or Hurricane Electric. | 


#### Command Example
``` ```

#### Human Readable Output



### censys-hosts-search
***
Returns previews of hosts matching a specified search query.


#### Base Command

`censys-hosts-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query used to search for hosts with matching attributes. Uses the Censys Search Language. | Required | 
| page_size | The maximum number of hits to return in each response (minimum of 0, maximum of 100). Default is 50. Default is 50. | Optional | 
| limit | The number of results to return. Default is 50. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Censys.HostSearch.autonomous_system.asn | Number | The autonomous system number \(ASN\) that the host is in. | 
| Censys.HostSearch.autonomous_system.bgp_prefix | String | The autonomous system's CIDR. | 
| Censys.HostSearch.autonomous_system.country_code | String | The autonomous system's two-letter, ISO 3166-1 alpha-2 country code \(e.g., US, CN, GB, RU\). | 
| Censys.HostSearch.autonomous_system.description | String | A brief description of the autonomous system. | 
| Censys.HostSearch.autonomous_system.name | String | The friendly name of the autonomous system. | 
| Censys.HostSearch.ip | String | The host’s IP address. | 
| Censys.HostSearch.location.continent | String | The continent of the host's detected location \(e.g., North America, Europe, Asia, South America, Africa, Oceania\) | 
| Censys.HostSearch.location.coordinates | Unknown | The estimated coordinates of the host's detected location. | 
| Censys.HostSearch.location.country | String | The country of the host's detected location. | 
| Censys.HostSearch.location.country_code | String | The two-letter ISO 3166-1 alpha-2 country code of the host's detected location \(e.g., US, CN, GB, RU\). | 
| Censys.HostSearch.location.registered_country | String | The host's registered country. | 
| Censys.HostSearch.location.registered_country_code | String | The registered country's two-letter, ISO 3166-1 alpha-2 country code \(e.g., US, CN, GB, RU\). | 
| Censys.HostSearch.location.timezone | String | The IANA time zone database name of the host's detected location. | 
| Censys.HostSearch.services.port | Number | The port the service was reached at. | 
| Censys.HostSearch.services.service_name | String | The name of the service on the port. This is typically the L7 protocol \(e.g., “HTTP”\); however, in the case that a more specific HTTP-based protocol is found \(e.g., Kubernetes or Prometheus\), the field will show that. This field indicates where protocol-specific data will be located. | 
| Censys.HostSearch.services.transport_protocol | String | The transport protocol \(known in OSI model as L4\) used to contact this service \(i.e., UDP or TCP\). | 


#### Command Example
``` ```

#### Human Readable Output



### censys-certificates-search
***
Retruns a list of certificates that match the given query.


#### Base Command

`censys-certificates-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query used to search for certificates with matching attributes. Uses the Censys Search Language. | Required | 
| page | The page tp return, Default is 1. Default is 1. | Optional | 
| Fields | The fields to return. | Optional | 
| limit | The number of results to return. Default is 50. Default is 50. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Censys.CertificateSearch.parsed.fingerprint_sha256 | String | SHA 256 fingerprint. | 
| Censys.CertificateSearch.parsed.issuer.organization | Unknown |  | 
| Censys.CertificateSearch.parsed.issuer_dn | String | Distinguished name of the entity that has signed and issued the certificate. | 
| Censys.CertificateSearch.parsed.names | Unknown | Common names for the entity. | 
| Censys.CertificateSearch.parsed.subject_dn | String | Distinguished name of the entity that the certificate belongs to. | 
| Censys.CertificateSearch.parsed.validity.end | String | Validity end date. | 
| Censys.CertificateSearch.parsed.validity.start | String | Validity start date. | 


#### Command Example
``` ```

#### Human Readable Output



### censys-certificate-view
***
Returns structured certificate data for the specified SHA-256.


#### Base Command

`censys-certificate-view`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The SHA-256 fingerprint of the requested certificate. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Censys.CertificateView.fingerprint_sha256 | String | The file SHA256. | 
| Censys.CertificateView.parent_spki_subject_fingerprint | String | Parent spki subject fingerprint | 
| Censys.CertificateView.parsed.fingerprint_sha1 | String | Certificate SHA1. | 
| Censys.CertificateView.parsed.fingerprint_md5 | String | Certificate MD5. | 
| Censys.CertificateView.parsed.names | Unknown | A list of subject names in the certificate, including the Subject CommonName and SubjectAltName DNSNames, IPAddresses and URIs. | 
| Censys.CertificateView.parsed.subject.common_name | String | Common Name | 
| Censys.CertificateView.parsed.subject.country | String | Country name. | 
| Censys.CertificateView.parsed.subject.locality | String | Locality name. | 
| Censys.CertificateView.parsed.subject.organization | String | Organization name. | 
| Censys.CertificateView.parsed.subject.province | String | Province name. | 
| Censys.CertificateView.parsed.issuer_dn | String | Issuer name. | 
| Censys.CertificateView.parsed.validity.end | Date | Timestamp of when certificate expires. Timezone is UTC. | 
| Censys.CertificateView.parsed.validity.start | Date | Timestamp of when certificate is first valid. Timezone is UTC. | 
| Censys.CertificateView.parsed.extensions.subject_alt_name.dns_names | Unknown | DNS Name entries. | 
| Censys.CertificateView.parsed.issuer.common_name | String | Common name. | 
| Censys.CertificateView.parsed.issuer.country | String | Country name. | 
| Censys.CertificateView.parsed.issuer.organization | String | Organization name. | 
| Censys.CertificateView.parsed.subject_dn | String | A canonical string representation of the subject name. | 
| Censys.CertificateView.parsed.validation_level | String | How the certificate is validated -- Domain validated \(DV\), Organization Validated \(OV\), Extended Validation \(EV\), or unknown. | 
| Censys.CertificateView.tags | Unknown | Tags | 


#### Command Example
``` ```

#### Human Readable Output



## Breaking changes from the previous version of this integration - CensysV2
%%FILL HERE%%
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
* *commandName* - this command was replaced by XXX.
* *commandName* - this command was replaced by XXX.

### Arguments
#### The following arguments were removed in this version:

In the *commandName* command:
* *argumentName* - this argument was replaced by XXX.
* *argumentName* - this argument was replaced by XXX.

#### The behavior of the following arguments was changed:

In the *commandName* command:
* *argumentName* - is now required.
* *argumentName* - supports now comma separated values.

### Outputs
#### The following outputs were removed in this version:

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

In the *commandName* command:
* *outputPath* - this output was replaced by XXX.
* *outputPath* - this output was replaced by XXX.

## Additional Considerations for this version
%%FILL HERE%%
* Insert any API changes, any behavioral changes, limitations, or restrictions that would be new to this version.
