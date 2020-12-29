This automation exports all custom certificate-related information from the Python Docker container and decode it using RFC. In addition, it will get the certificate located in the specified endpoint.

## Notes

---

After following the [tutorial](https://docs.paloaltonetworks.com/cortex/cortex-xsoar/6-0/cortex-xsoar-admin/docker/configure-python-docker-integrations-to-trust-custom-certificates) to update your custom certificate in `Cortex XSOAR Server`/ `Cortex XSOAR Engine`, validate the configuration applied using this script.

The script supports two modes of operation:

  1. **python**: Uses the Python built-in SSL library to detect the endpoint's certificates.
  2. **openssl**: will use the openssl client to detect the endpoint's certificates. Use this mode if the `python` mode fails for some reason.

When reporting issues always run this script with `debug-mode=true` and include the debug-mode log file.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| endpoint | The endpoint identifier IP address or URL:Port. If the port is not included, 443 will be used by default. |
| port | The endpoint port. Default is 443. |
| mode | Operation mode. Determines how the endpoint is inspected. Either using python built-in SSL or openssl client. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TroubleShoot.Engine.SSL/TLS.ShellVariables.SSL_CERT_FILE | The SSL_CERT_FILE environment variable. For example, "/etc/custom-python-ssl/certs.pem" | String |
| TroubleShoot.Engine.SSL/TLS.ShellVariables.CERT_FILE | The CERT_FILE environment variable. For example, "/etc/custom-python-ssl/certs.pem". | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.OrganizationalUnitName | The unit name of the organization that is the holder of the engine custom SSL certificate. For example, "Content". | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.OrganizationName | The name of the organization that is the holder of the engine custom SSL certificate. For example, "Cortex XSOAR". | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.BusinessCategory | The business category of the holder of the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.Title | The title of the holder of the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.SerialNumber | The serial number of the holder of the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.StateOrProvinceName | The state or province of the holder of the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.DomainComponent | The DNS domain name of the holder of the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.GivenName | The given name of the holder of the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.Pseudonym | The pseudonym of the holder of the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.JurisdictionStateOrProvinceName | The jurisdiction state or province of the holder of the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.GenerationQualifier | The generation qualifier of the holder of the engine custom SSL certificate. For example, 3rd generation. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.LocalityName | The locality of the holder of the engine custom SSL certificate. For example, "Birmingham". | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.SurName | The surname of the holder of the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.CommonName | The common name of the holder of the engine custom SSL certificate. For example, "Cortex XSOAR TLS". | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.JurisdictionLocalityName | The jurisdiction locality of the holder of the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.StreetAddress | The street address of the holder of the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.PostalCode | The postal code of the holder of the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.PostalAddress | The postal address of the holder of the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.JurisdictionCountryName | The jurisdiction country name of the holder of the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.CountryName | The country of the holder of the engine custom SSL certificate. For example, "GB". | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.EmailAddress | The email address of the holder of the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.DomainNameQualifier | The domain name qualifier of the holder of the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.OrganizationalUnitName | The unit name of the organization of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.OrganizationName | The name of the organization of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.BusinessCategory | The business category of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.Title | The title of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.SerialNumber | The serial number of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.StateOrProvinceName | The state or province of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.DomainComponent | The DNS domain name of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.GivenName | The given name of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.Pseudonym | The pseudonym of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.JurisdictionStateOrProvinceName | The jurisdiction state or province of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.GenerationQualifier | The generation qualifier of the authority that issued the engine custom SSL certificate. For example, 3rd generation. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.LocalityName | The locality of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.SurName | The surname of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.CommonName | The common name of the authority that issued the engine custom SSL certificate. For example, "Cortex XSOAR TLS". | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.JurisdictionLocalityName | The jurisdiction locality of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.StreetAddress | The street address of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.PostalCode | The postal code of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.PostalAddress | The postal address of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.JurisdictionCountryName | The jurisdiction country name of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.CountryName | The country of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.EmailAddress | The email address of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.DomainNameQualifier | The domain name qualifier of the authority that issued the engine custom SSL certificate. | String |
| TroubleShoot.Engine.SSL/TLS.Certificates.Decode.Extentions.IssuerAlternativeName | The alternate names of the issuer. | String |
| TroubleShoot.Engine.SSL/TLS.Certificates.Decode.Extentions.SubjectAlternativeName | The alternate names of the subject. | String |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.NotValidBefore | The beginning of the validity period for the certificate in UTC format. | Date |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.NotValidAfter | The end of the validity period for the certificate in UTC format. | Date |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Version| The version of the certificate. | Number |
| TroubleShoot.Engine.SSL/TLS.CustomCertificateAuthorities.Raw | The raw engine custom SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.OrganizationalUnitName | The unit name of the organization that is the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.OrganizationName | The name of the organization that is the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.BusinessCategory | The business category of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.Title | The title of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.SerialNumber | The serial number of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.StateOrProvinceName | The state or province of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.DomainComponent | The DNS domain name of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.GivenName | The given name of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.Pseudonym | The pseudonym of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.JurisdictionStateOrProvinceName | The jurisdiction state or province of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.GenerationQualifier | The generation qualifier of the holder of the endpoint SSL certificate. For example, 3rd generation. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.LocalityName | The locality of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.SurName | The surname of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.CommonName | The common name of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.JurisdictionLocalityName | The jurisdiction locality of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.StreetAddress | The street address of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.PostalCode | The postal code of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.PostalAddress | The postal address of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.JurisdictionCountryName | The jurisdiction country name of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.CountryName | The country of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.EmailAddress | The email address of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Subject.DomainNameQualifier | The domain name qualifier of the holder of the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.OrganizationalUnitName | The unit name of the organization of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.OrganizationName | The name of the organization of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.BusinessCategory | The business category of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.Title | The title of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.SerialNumber | The serial number of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.StateOrProvinceName | The state or province of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.DomainComponent | The DNS domain name of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.GivenName | The given name of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.Pseudonym | The pseudonym of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.JurisdictionStateOrProvinceName | The jurisdiction state or province of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.GenerationQualifier | The generation qualifier of the authority that issued the endpoint SSL certificate. For example, 3rd generation. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.LocalityName | The locality of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.SurName | The surname of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.CommonName | The common name of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.JurisdictionLocalityName | The jurisdiction locality of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.StreetAddress | The street address of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.PostalCode | The postal code of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.PostalAddress | The postal address of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.JurisdictionCountryName | The jurisdiction country name of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.CountryName | The country of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.EmailAddress | The email address of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Issuer.DomainNameQualifier | The domain name qualifier of the authority that issued the endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Extentions.IssuerAlternativeName | The alternate names of the issuer. | String |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Decode.Extentions.SubjectAlternativeName | The alternate names of the subject. | String |
| TroubleShoot.Endpoint.SSL/TLS.CustomCertificateAuthorities.Decode.NotValidBefore | The beginning of the validity period for the certificate in UTC format. | Date |
| TroubleShoot.Endpoint.SSL/TLS.CustomCertificateAuthorities.Decode.NotValidAfter | The end of the validity period for the certificate in UTC format. | Date |
| TroubleShoot.Endpoint.SSL/TLS.CustomCertificateAuthorities.Decode.Version| The version of the certificate. | Number |
| TroubleShoot.Endpoint.SSL/TLS.Certificates.Raw | The raw endpoint SSL certificate. | String |
| TroubleShoot.Endpoint.SSL/TLS.Identifier | The endpoint SSL identifier. | String |

#### Command Example

```CertificatesTroubleshoot endpoint=google.com port=443```

#### Context Example

```
{
    "TroubleShoot": {
        "Engine": {
            "SSL/TLS": {
                "ShellVariables": {
                    "SSL_CERT_FILE": "/etc/custom-python-ssl/certs.pem", 
                    "CERT_FILE": "/etc/custom-python-ssl/certs.pem"
                }, 
                "CustomCertificateAuthorities": [
                    {
                        "Decode": {
                            "Subject": {
                                "OrganizationalUnitName": [
                                    "Content"
                                ], 
                                "OrganizationName": [
                                    "Demisto"
                                ], 
                                "BusinessCategory": null, 
                                "Title": null, 
                                "SerialNumber": null, 
                                "StateOrProvinceName": [
                                    "Hamerkaz"
                                ], 
                                "DomainComponent": null, 
                                "GivenName": null, 
                                "Pseudonym": null, 
                                "JurisdictionStateOrProvinceName": null, 
                                "GenerationQualifier": null, 
                                "LocalityName": [
                                    "Tel Aviv"
                                ], 
                                "SurName": null, 
                                "CommonName": [
                                    "Demisto TLS"
                                ], 
                                "JurisdictionLocalityName": null, 
                                "StreetAddress": null, 
                                "PostalCode": null, 
                                "PostalAddress": null, 
                                "JurisdictionCountryName": null, 
                                "CountryName": [
                                    "IL"
                                ], 
                                "EmailAddress": [
                                    "test@gmail.com""
                                ], 
                                "DomainNameQualifier": null
                            }, 
                            "Issuer": {
                                "OrganizationalUnitName": [
                                    "Content"
                                ], 
                                "OrganizationName": [
                                    "Demisto"
                                ], 
                                "BusinessCategory": null, 
                                "Title": null, 
                                "SerialNumber": null, 
                                "StateOrProvinceName": [
                                    "Hamerkaz"
                                ], 
                                "DomainComponent": null, 
                                "GivenName": null, 
                                "Pseudonym": null, 
                                "JurisdictionStateOrProvinceName": null, 
                                "GenerationQualifier": null, 
                                "LocalityName": [
                                    "Tel Aviv"
                                ], 
                                "SurName": null, 
                                "CommonName": [
                                    "Demisto TLS"
                                ], 
                                "JurisdictionLocalityName": null, 
                                "StreetAddress": null, 
                                "PostalCode": null, 
                                "PostalAddress": null, 
                                "JurisdictionCountryName": null, 
                                "CountryName": [
                                    "IL"
                                ], 
                                "EmailAddress": [
                                    "test@gmail.com""
                                ], 
                                "DomainNameQualifier": null
                            }
                        }, 
                        "Raw": "-----BEGIN CERTIFICATE-----\nxxxxx\n-----END CERTIFICATE-----\n"
                    }
                ]
            }
        }, 
        "Endpoint": {
            "SSL/TLS": {
                "Certificates": [
                    {
                        "Decode": {
                            "Subject": {
                                "OrganizationalUnitName": [
                                    "Test"
                                ], 
                                "OrganizationName": [
                                    "Content"
                                ], 
                                "BusinessCategory": null, 
                                "Title": null, 
                                "SerialNumber": null, 
                                "StateOrProvinceName": [
                                    "Demisto"
                                ], 
                                "DomainComponent": null, 
                                "GivenName": null, 
                                "Pseudonym": null, 
                                "JurisdictionStateOrProvinceName": null, 
                                "GenerationQualifier": null, 
                                "LocalityName": null, 
                                "SurName": null, 
                                "CommonName": [
                                    "test.compute.amazonaws.com"
                                ], 
                                "JurisdictionLocalityName": null, 
                                "StreetAddress": null, 
                                "PostalCode": null, 
                                "PostalAddress": null, 
                                "JurisdictionCountryName": null, 
                                "CountryName": [
                                    "IL"
                                ], 
                                "EmailAddress": [
                                    "test@gmail.com""
                                ], 
                                "DomainNameQualifier": null
                            }, 
                            "Issuer": {
                                "OrganizationalUnitName": [
                                    "Content"
                                ], 
                                "OrganizationName": [
                                    "Demisto"
                                ], 
                                "BusinessCategory": null, 
                                "Title": null, 
                                "SerialNumber": null, 
                                "StateOrProvinceName": [
                                    "Hamerkaz"
                                ], 
                                "DomainComponent": null, 
                                "GivenName": null, 
                                "Pseudonym": null, 
                                "JurisdictionStateOrProvinceName": null, 
                                "GenerationQualifier": null, 
                                "LocalityName": [
                                    "Tel Aviv"
                                ], 
                                "SurName": null, 
                                "CommonName": [
                                    "Demisto TLS"
                                ], 
                                "JurisdictionLocalityName": null, 
                                "StreetAddress": null, 
                                "PostalCode": null, 
                                "PostalAddress": null, 
                                "JurisdictionCountryName": null, 
                                "CountryName": [
                                    "IL"
                                ], 
                                "EmailAddress": [
                                    "test@gmail.com"
                                ], 
                                "DomainNameQualifier": null
                            }
                        }, 
                        "Raw": "-----BEGIN CERTIFICATE-----\nxxxx\n-----END CERTIFICATE-----\n"
                    }
                ], 
                "Identifier": "test.compute.amazonaws.com",
                "NotValidBefore": "2020-09-22 11:37:45",
                "NotValidAfter": "2025-09-21 11:37:45",
                "Version": 0,
                "Extentions: {
                    "IssuerAlternativeName": [*.google.com, *.appengine.google.com],
                    "SubjectAlternativeName": [*.google.com, *.appengine.google.com]
                }
            }
        }
    }
}
```

#### Human Readable Output

> ## Docker container engine - custom certificate
> ### Enviorment variables
> |CERT_FILE|SSL_CERT_FILE|
> |---|---|
> | /etc/custom-python-ssl/certs.pem | /etc/custom-python-ssl/certs.pem |
>
> ### General
> |NotValidBefore|NotValidAfter|Version|
> |---|---|---|
> | 2020-09-22 15:22:19 | 2020-12-15 15:22:19 | 2 |
> ### Issuer
> |CommonName|CountryName|EmailAddress|LocalityName|OrganizationName|OrganizationalUnitName|StateOrProvinceName|
> |---|---|---|---|---|---|---|
> | Demisto TLS | IL | all@paloaltonetworks.com | Tel Aviv | Demisto | Content | Hamerkaz |
> ### Subject
> |CommonName|CountryName|EmailAddress|LocalityName|OrganizationName|OrganizationalUnitName|StateOrProvinceName|
> |---|---|---|---|---|---|---|
> | Demisto TLS | IL | all@paloaltonetworks.com | Tel Aviv | Demisto | Content | Hamerkaz |
>
> ## Endpoint certificate - ec2-54-220-131-136.eu-west-1.compute.amazonaws.com
> ### General
> |NotValidBefore|NotValidAfter|Version|
> |---|---|---|
> | 2020-09-22 15:22:19 | 2020-12-15 15:22:19 | 2 |
> ### Issuer
> |CommonName|CountryName|EmailAddress|LocalityName|OrganizationName|OrganizationalUnitName|StateOrProvinceName|
> |---|---|---|---|---|---|---|
> | Demisto TLS | IL | all@paloaltonetworks.com | Tel Aviv | Demisto | Content | Hamerkaz |
> ### Subject
> |CommonName|CountryName|EmailAddress|OrganizationName|OrganizationalUnitName|StateOrProvinceName|
> |---|---|---|---|---|---|
> | ec2-54-220-131-136.eu-west-1.compute.amazonaws.com | IL | test@gmail.com | Content | Test | Demisto |
> ### Extentions
> |IssuerAlternativeName|
> |---|
> | *.google.com,*.android.com,*.appengine.google.com,*.bdn.dev,*.cloud.google.com |


 
