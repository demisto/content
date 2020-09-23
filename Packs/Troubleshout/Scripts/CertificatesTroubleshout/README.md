This automation will export all Certificates related information from the python docker container and decode it by RFC. In addition, it will get the certificate located in endpoint.
## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Demisto Version | 0.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| endpoint | Endpoint identifier IP/URL:Port, If port not included will use 443 by default. |
| port | Endpoint port, By default 443. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TroubleShout.TroubleShout.Engine.SSL/TLS.ShellVariables.SSL_CERT_FILE | SSL_CERT_FILE shell variable | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.ShellVariables.CERT_FILE | CERT_FILE shell variable | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.OrganizationalUnitName | Subject \(Certificate holder\) OrganizationalUnitName | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.OrganizationName | Engine custom certificate - Subject \(Certificate holder\) Organizational Unit Name. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.BusinessCategory | Engine custom certificate - Subject \(Certificate holder\) Business Category. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.Title | Engine custom certificate - Subject \(Certificate holder\) Title. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.SerialNumber | Engine custom certificate - Subject \(Certificate holder\) Serial Number. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.StateOrProvinceName | Engine custom certificate - Subject \(Certificate holder\) State Or ProvinceName. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.DomainComponent | Engine custom certificate - Subject \(Certificate holder\) Domain Component. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.GivenName | Engine custom certificate - Subject \(Certificate holder\) GivenName. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.Pseudonym | Engine custom certificate - Subject \(Certificate holder\) Pseudonym. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.JurisdictionStateOrProvinceName | Engine custom certificate - Subject \(Certificate holder\) Jurisdiction State Or ProvinceName. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.GenerationQualifier | Engine custom certificate - Subject \(Certificate holder\) Generation Qualifier. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.LocalityName | Engine custom certificate - Subject \(Certificate holder\) Locality Name. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.SurName | Engine custom certificate - Subject \(Certificate holder\) Sur Name. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.CommonName | Engine custom certificate - Subject \(Certificate holder\) Common Name | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.JurisdictionLocalityName | Engine custom certificate - Subject \(Certificate holder\) Jurisdiction Locality Name. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.StreetAddress | Engine custom certificate - Subject \(Certificate holder\) Street Address. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.PostalCode | Engine custom certificate - Subject \(Certificate holder\) Postal Code. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.PostalAddress | Engine custom certificate - Subject \(Certificate holder\) Postal Address. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.JurisdictionCountryName | Engine custom certificate - Subject \(Certificate holder\) Jurisdiction Country Name. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.CountryName | Engine custom certificate - Subject \(Certificate holder\) Country Name. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.EmailAddress | Engine custom certificate - Subject \(Certificate holder\) OrganizationalUnitName | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Subject.DomainNameQualifier | Engine custom certificate - Issuer \(Authority issued the certificate\) DomainName Qualifier. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.OrganizationalUnitName | Engine custom certificate - Issuer \(Authority issued the certificate\) Organizational Unit Name. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.OrganizationName | Engine custom certificate - Issuer \(Authority issued the certificate\) Organization Name. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.BusinessCategory | Engine custom certificate - Issuer \(Authority issued the certificate\) Business Category. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.Title | Engine custom certificate - Issuer \(Authority issued the certificate\) Title. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.SerialNumber | Engine custom certificate - Issuer \(Authority issued the certificate\) Serial Number. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.StateOrProvinceName | Engine custom certificate - Issuer \(Authority issued the certificate\) State Or ProvinceName. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.DomainComponent | Engine custom certificate - Issuer \(Authority issued the certificate\) Domain Component. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.GivenName | Engine custom certificate - Issuer \(Authority issued the certificate\) Given Name. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.Pseudonym | Engine custom certificate - Issuer \(Authority issued the certificate\) Pseudonym. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.JurisdictionStateOrProvinceName | Engine custom certificate - Issuer \(Authority issued the certificate\) Jurisdiction State Or ProvinceName | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.GenerationQualifier | Engine custom certificate - Issuer \(Authority issued the certificate\) Generation Qualifier. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.LocalityName | Engine custom certificate - Issuer \(Authority issued the certificate\) Locality Name. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.SurName | Engine custom certificate - Issuer \(Authority issued the certificate\) Sur Name. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.CommonName | Engine custom certificate - Issuer \(Authority issued the certificate\) Common Name. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.JurisdictionLocalityName | Engine custom certificate - Issuer \(Authority issued the certificate\) Jurisdiction Locality Name. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.StreetAddress | Engine custom certificate - Issuer \(Authority issued the certificate\) Street Address. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.PostalCode | Engine custom certificate - Issuer \(Authority issued the certificate\) Postal Code. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.PostalAddress | Engine custom certificate - Issuer \(Authority issued the certificate\) Postal Address. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.JurisdictionCountryName | Engine custom certificate - Issuer \(Authority issued the certificate\) Jurisdiction Country Name. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.CountryName | Engine custom certificate - Issuer \(Authority issued the certificate\) Country Name. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.EmailAddress | Engine custom certificate - Issuer \(Authority issued the certificate\) Email Address. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Decode.Issuer.DomainNameQualifier | Engine custom certificate - Issuer \(Authority issued the certificate\) Domain Name Qualifier. | String |
| TroubleShout.TroubleShout.Engine.SSL/TLS.CustomCertificateAuthorities.Raw | Engine custom certificate   Raw. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.OrganizationalUnitName | Enpoint certificate - Subject \(Certificate holder\) Organizational Unit Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.OrganizationName | Enpoint certificate - Subject \(Certificate holder\) Organization Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.BusinessCategory | Enpoint certificate - Subject \(Certificate holder\) Business Category. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.Title | Enpoint certificate - Subject \(Certificate holder\) Title. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.SerialNumber | Enpoint certificate - Subject \(Certificate holder\) SerialNumber. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.StateOrProvinceName | Enpoint certificate - Subject \(Certificate holder\)StateOrProvinceName. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.DomainComponent | Enpoint certificate - Subject \(Certificate holder\) DomainComponent. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.GivenName | Enpoint certificate - Subject \(Certificate holder\) Given Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.Pseudonym | Enpoint certificate - Subject \(Certificate holder\) Pseudonym. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.JurisdictionStateOrProvinceName | Enpoint certificate - Subject \(Certificate holder\) Jurisdiction State Or ProvinceName. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.GenerationQualifier | Enpoint certificate - Subject \(Certificate holder\) Generation Qualifier. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.LocalityName | Enpoint certificate - Subject \(Certificate holder\) Locality Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.SurName | Enpoint certificate - Subject \(Certificate holder\) Sur Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.CommonName | Enpoint certificate - Subject \(Certificate holder\) Common Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.JurisdictionLocalityName | Enpoint certificate - Subject \(Certificate holder\) Jurisdiction Locality Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.StreetAddress | Enpoint certificate - Subject \(Certificate holder\) Street Address. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.PostalCode | Enpoint certificate - Subject \(Certificate holder\) Postal Code. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.PostalAddress | Enpoint certificate - Subject \(Certificate holder\) Postal Address. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.JurisdictionCountryName | Enpoint certificate - Subject \(Certificate holder\) Jurisdiction Country Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.CountryName | Enpoint certificate - Subject \(Certificate holder\) CountryName. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.EmailAddress | Enpoint certificate - Subject \(Certificate holder\) Email Address. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Subject.DomainNameQualifier | Enpoint certificate - Subject \(Certificate holder\) Domain Name Qualifier. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.OrganizationalUnitName | Enpoint certificate - Issuer \(Authority issued the certificate\) Organizational Unit Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.OrganizationName | Enpoint certificate - Issuer \(Authority issued the certificate\) Organization Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.BusinessCategory | Enpoint certificate - Issuer \(Authority issued the certificate\) Business Category. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.Title | Enpoint certificate - Issuer \(Authority issued the certificate\) Title. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.SerialNumber | Enpoint certificate - Issuer \(Authority issued the certificate\) SerialNumber. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.StateOrProvinceName | Enpoint certificate - Issuer \(Authority issued the certificate\) State Or Province Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.DomainComponent | Enpoint certificate - Issuer \(Authority issued the certificate\) Domain Component. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.GivenName | Enpoint certificate - Issuer \(Authority issued the certificate\) Given Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.Pseudonym | Enpoint certificate - Issuer \(Authority issued the certificate\) Pseudonym. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.JurisdictionStateOrProvinceName | Enpoint certificate - Issuer \(Authority issued the certificate\) Jurisdiction State Or Province Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.GenerationQualifier | Enpoint certificate - Issuer \(Authority issued the certificate\) Generation Qualifier | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.LocalityName | Enpoint certificate - Issuer \(Authority issued the certificate\) Locality Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.SurName | Enpoint certificate - Issuer \(Authority issued the certificate\) Sur Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.CommonName | Enpoint certificate - Issuer \(Authority issued the certificate\) Common Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.JurisdictionLocalityName | Enpoint certificate - Issuer \(Authority issued the certificate\) Jurisdiction Locality Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.StreetAddress | Enpoint certificate - Issuer \(Authority issued the certificate\) Street Address. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.PostalCode | Enpoint certificate - Issuer \(Authority issued the certificate\) Postal Code. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.PostalAddress | Enpoint certificate - Issuer \(Authority issued the certificate\) Postal Address. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.JurisdictionCountryName | Enpoint certificate - Issuer \(Authority issued the certificate\) Jurisdiction Country Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.CountryName | Enpoint certificate - Issuer \(Authority issued the certificate\) Country Name. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.EmailAddress | Enpoint certificate - Issuer \(Authority issued the certificate\) Email Address. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Decode.Issuer.DomainNameQualifier | Enpoint certificate - Issuer \(Authority issued the certificate\) Domain Name Qualifier. | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Certificates.Raw | Enpoint certificate raw | String |
| TroubleShout.TroubleShout.Endpoint.SSL/TLS.Identifier | Enpoint Identifier. | String |

#### Command Example
```CertificatesTroubleshout endpoint=test.compute.amazonaws.com port=5443```

#### Context Example
```
{
    "TroubleShout": {
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
                "Identifier": "test.compute.amazonaws.com"
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
> ### Issuer
> |CommonName|CountryName|EmailAddress|LocalityName|OrganizationName|OrganizationalUnitName|StateOrProvinceName|
> |---|---|---|---|---|---|---|
> | Demisto TLS | IL | all@paloaltonetworks.com | Tel Aviv | Demisto | Content | Hamerkaz |
> ### Subject
> |CommonName|CountryName|EmailAddress|LocalityName|OrganizationName|OrganizationalUnitName|StateOrProvinceName|
> |---|---|---|---|---|---|---|
> | Demisto TLS | IL | all@paloaltonetworks.com | Tel Aviv | Demisto | Content | Hamerkaz |
> ## Endpoint certificate - ec2-54-220-131-136.eu-west-1.compute.amazonaws.com
> ### Issuer
> |CommonName|CountryName|EmailAddress|LocalityName|OrganizationName|OrganizationalUnitName|StateOrProvinceName|
> |---|---|---|---|---|---|---|
> | Demisto TLS | IL | all@paloaltonetworks.com | Tel Aviv | Demisto | Content | Hamerkaz |
> ### Subject
> |CommonName|CountryName|EmailAddress|OrganizationName|OrganizationalUnitName|StateOrProvinceName|
> |---|---|---|---|---|---|
> | ec2-54-220-131-136.eu-west-1.compute.amazonaws.com | IL | test@gmail.com | Content | Test | Demisto |


 
