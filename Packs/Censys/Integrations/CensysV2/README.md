Censys is a search engine that allows computer scientists to ask questions about the devices and networks that compose the internet. Driven by internet-wide scanning, Censys lets researchers find specific hosts and create aggregate reports on how devices, and certificates are configured and deployed.
This integration was integrated and tested with version 2.0 of Censys.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#additional-considerations-for-this-version).

## Configure Censys v2 in Cortex


| **Parameter** | **Required** |
| --- | --- |
| App ID | True |
| Secret | True |
| Trust any certificate (not secure) | False |
| Use system proxy settings | False |
| Labels premium feature available | False |
| IP and Domain Malicious labels | False |
| IP and Domain Suspicious labels | False |
| Malicious labels threshold | False |
| Suspicious labels threshold | False |


## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### cen-view
***
Returns detailed information for an IP address or SHA256 within the specified index.


#### Base Command

`cen-view`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | The IP address of the requested host. | Required | 
| index | The index from which to retrieve data. Possible values are: ipv4, certificates. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Censys.View.autonomous_system.asn | Number | The autonomous system number \(ASN\) that the host is in. | 
| Censys.View.autonomous_system.bgp_prefix | String | The autonomous system's CIDR. | 
| Censys.View.autonomous_system.country_code | String | The autonomous system's two-letter, ISO 3166-1 alpha-2 country code \(e.g., US, CN, GB, RU\). | 
| Censys.View.autonomous_system.description | String | A brief description of the autonomous system. | 
| Censys.View.autonomous_system.name | String | The friendly name of the autonomous system. | 
| Censys.View.autonomous_system_updated_at | Date | When the autonomous system was updated. | 
| Censys.View.dns.names | String | DNS Names. | 
| Censys.View.dns.records | Unknown | DNS records. | 
| Censys.View.dns.reverse_dns.names | String | Reverse DNS names. | 
| Censys.View.ip | String | The host’s IP address. | 
| Censys.View.last_updated_at | Date | When the host was last updated. | 
| Censys.View.location.continent | String | The continent of the host's detected location \(e.g., North America, Europe, Asia, South America, Africa, Oceania\). | 
| Censys.View.location.coordinates | Unknown | The estimated coordinates of the host's detected location. | 
| Censys.View.location.country | String | The name of the country of the host's detected location. | 
| Censys.View.location.country_code | String | The two-letter ISO 3166-1 alpha-2 country code of the host's detected location \(e.g., US, CN, GB, RU\). | 
| Censys.View.location.postal_code | String | The postal code \(if applicable\) of the host's detected location. | 
| Censys.View.location.registered_country | String | The English name of the host's registered country. | 
| Censys.View.location.registered_country_code | String | The registered country's two-letter, ISO 3166-1 alpha-2 country code \(e.g., US, CN, GB, RU\). | 
| Censys.View.location.timezone | String | The IANA time zone database name of the host's detected location. | 
| Censys.View.services.dns | Unknown | DNS information. | 
| Censys.View.services.extended_service_name | String | The service name with the TLS encryption indicator if the service is using it. | 
| Censys.View.services.observed_at | Date | The UTC timestamp of when Censys scanned the service. | 
| Censys.View.services.perspective_id | String | The upstream internet service provider Censys peered with to scan the service - NTT Communications, TATA, Telia Carrier, or Hurricane Electric. | 
| Censys.View.services.port | Number | The port the service was reached at. | 
| Censys.View.services.service_name | String | The name of the service on the port. This is typically the L7 protocol \(e.g., “HTTP”\); however, in the case that a more specific HTTP-based protocol is found \(e.g., Kubernetes or Prometheus\), the field will show that. This field indicates where protocol-specific data will be located. | 
| Censys.View.services.source_ip | String | The IP address from which Censys scanned the service. | 
| Censys.View.services.transport_protocol | String | The transport protocol \(known in OSI model as L4\) used to contact this service \(i.e., UDP or TCP\). | 
| Censys.View.services.banner | String | The banner as a part of the protocol scan. That field will be nested in the protocol-specific data under the service_name field. | 
| Censys.View.services.tls.certificates | Unknown | A subset of the parsed details of the certificate, including the issuer, subject, fingerprint, names, public keys, and signature. | 
| Censys.View.services.tls.session_ticket | Unknown | Details about the session ticket provided by the server at the end of the TLS handshake. | 
| Censys.View.ct | Unknown | When a certificate was added to a CT log. | 
| Censys.View.fingerprint_sha256 | String | The SHA2-256 digest over the DER encoding of the certificate. | 
| Censys.View.metadata | Unknown | Whether the certificate was \(ever\) seen during a Censys scan of the internet. | 
| Censys.View.parent_spki_subject_fingerprint | String | Parent simple public key infrastructure \(SPKI\) subject fingerprint. | 
| Censys.View.parsed.extensions | Unknown | Additional fields that extend the X.509 spec. | 
| Censys.View.parsed.fingerprint_md5 | String | The MD5 digest over the DER encoding of the certificate. | 
| Censys.View.parsed.fingerprint_sha1 | String | The SHA1 digest over the DER encoding of the certificate. | 
| Censys.View.parsed.fingerprint_sha256 | String | The SHA2-256 digest over the DER encoding of the certificate. | 
| Censys.View.parsed.issuer.common_name | String | Common name. | 
| Censys.View.parsed.issuer.country | String | Country name. | 
| Censys.View.parsed.issuer.organization | String | Organization name. | 
| Censys.View.parsed.issuer_dn | String | Information about the certificate authority that issued the certificate. | 
| Censys.View.parsed.names | String | Any names for which the certificate can be used for identity verification. | 
| Censys.View.parsed.redacted | Boolean | Indicates whether the certificate redacted. | 
| Censys.View.parsed.serial_number | String | The issuer-specific identifier of the certificate. | 
| Censys.View.parsed.signature.self_signed | Boolean | Indicates whether the subject key was also used to sign the certificate. | 
| Censys.View.parsed.signature.signature_algorithm.name | String | Name of signature algorithm, e.g., SHA1-RSA or ECDSA-SHA512. Unknown algorithms get an integer ID. | 
| Censys.View.parsed.signature.signature_algorithm.oid | String | The object identifier of the signature algorithm, in dotted-decimal notation. | 
| Censys.View.parsed.signature.valid | Boolean | Whether the signature is valid. | 
| Censys.View.parsed.signature.value | String | Contents of the signature as a bit string. | 
| Censys.View.parsed.signature_algorithm.name | String | Name of the signature algorithm, e.g., SHA1-RSA or ECDSA-SHA512. Unknown algorithms get an integer ID. | 
| Censys.View.parsed.signature_algorithm.oid | String | The object identifier of the signature algorithm, in dotted-decimal notation. | 
| Censys.View.parsed.spki_subject_fingerprint | String | The SHA2-256 digest over the DER encoding of the certificate's SubjectPublicKeyInfo, as a hexadecimal string. | 
| Censys.View.parsed.subject.common_name | String | Common name. | 
| Censys.View.parsed.subject.country | String | Country name. | 
| Censys.View.parsed.subject.locality | String | Locality name. | 
| Censys.View.parsed.subject.organization | String | The name of the organization to which the certificate was issued, if available. | 
| Censys.View.parsed.subject.province | String | State of province name. | 
| Censys.View.parsed.subject_dn | String | Information about the entity that was issued the certificate. | 
| Censys.View.parsed.subject_key_info.ecdsa_public_key | Unknown | The public portion of an ECDSA asymmetric key. | 
| Censys.View.parsed.subject_key_info.fingerprint_sha256 | String | The SHA2-256 digest calculated over the certificate's DER encoding. | 
| Censys.View.parsed.subject_key_info.key_algorithm.name | String | Name of public key type, e.g., RSA or ECDSA. | 
| Censys.View.parsed.tbs_fingerprint | String | The SHA2-256 digest over the DER encoding of the certificate's TBSCertificate. | 
| Censys.View.parsed.tbs_noct_fingerprint | String | The SHA2-256 digest over the DER encoding of the certificate's TBSCertificate with any CT extensions omitted. | 
| Censys.View.parsed.validation_level | String | How the certificate is validated - Domain validated \(DV\), Organization Validated \(OV\), Extended Validation \(EV\), or unknown. | 
| Censys.View.parsed.validity.end | Date | Timestamp of when the certificate expires. Time zone is UTC. | 
| Censys.View.parsed.validity.length | Number | The length of time, in seconds, that the certificate is valid. | 
| Censys.View.parsed.validity.start | Date | Timestamp of when certificate is first valid. Time zone is UTC. | 
| Censys.View.parsed.version | Number | The x.509 certificate version number. | 
| Censys.View.precert | Boolean | Whether the certificate is pre-cert. | 
| Censys.View.raw | String | The raw certificate. | 
| Censys.View.tags | String | Tags applied to the certificate. | 
| Censys.View.validation | Unknown | Whether the certificate is trusted by modern web browsers \(Mozilla NSS, Microsoft, and Apple\). | 
| Censys.View.zlint | Unknown | Whether the certificate has any zlint errors. | 
| IP.Address | String | IP address | 
| IP.ASN | String | The autonomous system name for the IP address, for example: "AS8948". | 
| IP.Geo.Location | String | The geolocation where the IP address is located, in the format: latitude:longitude. | 
| IP.Geo.Country | String | The country in which the IP address is located. | 
| IP.Geo.Description | String | Additional information about the location. | 
| IP.ASOwner | String | The autonomous system owner of the IP. | 
| DBotScore.Indicator | String | The indicator that was tested. | 
| DBotScore.Type | String | The indicator type. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| DBotScore.Score | Number | The actual score. | 

#### Command example
```!cen-view index=ipv4 query=8.8.8.8```
#### Context Example
```json
{
    "Censys": {
        "View": {
            "autonomous_system": {
                "asn": 15169,
                "bgp_prefix": "8.8.8.0/24",
                "country_code": "US",
                "description": "GOOGLE",
                "name": "GOOGLE"
            },
            "autonomous_system_updated_at": "2022-08-19T04:12:34.865059Z",
            "dns": {
                "names": [
                    "test.com.",
                    "uuu.mkppy.site.",
                    "hisports.club.",
                    "domain.com.",
                    "roidgames.de.",
                    "svhasso.duckdns.org.",
                    "albertogozzi.it.",
                    "prod.rialtic.app."
                ],
                "records": {
                    "1508cleveland.duckdns.org": {
                        "record_type": "A",
                        "resolved_at": "2021-10-02T06:16:39.231714247Z"
                    },
                    "albertogozzi.it": {
                        "record_type": "A",
                        "resolved_at": "2021-10-02T01:15:04.162523844Z"
                    },
                    "alpha.lab.toshokan.fr": {
                        "record_type": "A",
                        "resolved_at": "2021-10-03T14:18:01.127044067Z"
                    }
                },
                "reverse_dns": {
                    "names": [
                        "dns.google"
                    ],
                    "resolved_at": "2022-08-23T00:07:13.195583925Z"
                }
            },
            "ip": "8.8.8.8",
            "last_updated_at": "2022-08-30T06:39:12.356Z",
            "location": {
                "continent": "North America",
                "coordinates": {
                    "latitude": 37.751,
                    "longitude": -97.822
                },
                "country": "United States",
                "country_code": "US",
                "postal_code": "",
                "registered_country": "United States",
                "registered_country_code": "US",
                "timezone": "America/LA"
            },
            "location_updated_at": "2022-08-24T19:21:03.836386Z",
            "services": [
                {
                    "_decoded": "dns",
                    "dns": {
                        "answers": [
                            {
                                "name": "ip.parrotdns.com.",
                                "response": "1.2.3.4",
                                "type": "A"
                            },
                            {
                                "name": "ip.parrotdns.com.",
                                "response": "5.6.7.8",
                                "type": "A"
                            }
                        ],
                        "edns": {
                            "do": true,
                            "udp": 512,
                            "version": 0
                        },
                        "questions": [
                            {
                                "name": "ip.parrotdns.com.",
                                "response": ";ip.parrotdns.com.\tIN\t A",
                                "type": "A"
                            }
                        ],
                        "r_code": "SUCCESS",
                        "resolves_correctly": true,
                        "server_type": "FORWARDING"
                    },
                    "extended_service_name": "DNS",
                    "observed_at": "2022-08-30T06:39:12.150877871Z",
                    "perspective_id": "PERSPECTIVE_TATA",
                    "port": 53,
                    "service_name": "DNS",
                    "source_ip": "1.2.3.4",
                    "transport_protocol": "UDP",
                    "truncated": false
                },
                {
                    "_decoded": "http",
                    "_encoding": {
                        "banner": "DISPLAY_UTF8",
                        "banner_hex": "DISPLAY_HEX",
                        "certificate": "DISPLAY_HEX"
                    },
                    "banner": "banner",
                    "banner_hex": "485454502f312e312033303220466f756e640d0a582d436f6e74656e742d547970652d4f7074696f6e733a206e6f736e6966660d0a4163636573732d436f6e74726f6c2d416c6c6f772d4f726967696e3a202a0d0a4c6f636174696f6e3a2068747470733a2f2f646e732e676f6f676c652f0d0a446174653a20203c52454441435445443e0a436f6e74656e742d547970653a20746578742f68746d6c3b20636861727365743d5554462d380d0a5365727665723a2048545450207365727665722028756e6b6e6f776e290d0a436f6e74656e742d4c656e6774683a203231360d0a582d5853532d50726f74656374696f6e3a20300d0a582d4672616d652d4f7074696f6e733a2053414d454f524947494e0d0a416c742d5376633a2068333d223a343433223b206d613d323539323030302c68332d32393d223a343433223b206d613d323539323030302c68332d513035303d223a343433223b206d613d323539323030302c68332d513034363d223a343433223b206d613d323539323030302c68332d513034333d223a343433223b206d613d323539323030302c717569633d223a343433223b206d613d323539323030303b20763d2234362c3433220d0a",
                    "certificate": "5c2d6869e805696c328d7ba5acd7d347b46e1e03d7ed65886bf2df55f41d01fd",
                    "extended_service_name": "HTTPS",
                    "http": {
                        "request": {
                            "headers": {
                                "Accept": [
                                    "*/*"
                                ],
                                "User_Agent": [
                                    "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)"
                                ],
                                "_encoding": {
                                    "Accept": "DISPLAY_UTF8",
                                    "User_Agent": "DISPLAY_UTF8"
                                }
                            },
                            "method": "GET",
                            "uri": "https://8.8.8.8/"
                        },
                        "response": {
                            "_encoding": {
                                "body": "DISPLAY_UTF8",
                                "body_hash": "DISPLAY_UTF8",
                                "html_tags": "DISPLAY_UTF8",
                                "html_title": "DISPLAY_UTF8"
                            },
                            "body": "test",
                            "body_hash": "sha1:1fd84b37b709256752fe1f865f86b5bec0512345",
                            "body_size": 216,
                            "headers": {
                                "Access_Control_Allow_Origin": [
                                    "*"
                                ],
                                "Alt_Svc": [
                                    "alt text"
                                ],
                                "Content_Length": [
                                    "216"
                                ],
                                "Content_Type": [
                                    "text/html; charset=UTF-8"
                                ],
                                "Date": [
                                    "<REDACTED>"
                                ],
                                "Location": [
                                    "https://dns.google/"
                                ],
                                "Server": [
                                    "HTTP server (unknown)"
                                ],
                                "X_Content_Type_Options": [
                                    "nosniff"
                                ],
                                "X_Frame_Options": [
                                    "SAMEORIGIN"
                                ],
                                "X_Xss_Protection": [
                                    "0"
                                ],
                                "_encoding": {
                                    "Access_Control_Allow_Origin": "DISPLAY_UTF8",
                                    "Alt_Svc": "DISPLAY_UTF8",
                                    "Content_Length": "DISPLAY_UTF8",
                                    "Content_Type": "DISPLAY_UTF8",
                                    "Date": "DISPLAY_UTF8",
                                    "Location": "DISPLAY_UTF8",
                                    "Server": "DISPLAY_UTF8",
                                    "X_Content_Type_Options": "DISPLAY_UTF8",
                                    "X_Frame_Options": "DISPLAY_UTF8",
                                    "X_Xss_Protection": "DISPLAY_UTF8"
                                }
                            },
                            "html_tags": [
                                "<TITLE>302 Moved</TITLE>",
                                "<meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">"
                            ],
                            "html_title": "302 Moved",
                            "protocol": "HTTP/1.1",
                            "status_code": 302,
                            "status_reason": "Found"
                        },
                        "supports_http2": true
                    },
                    "observed_at": "2022-08-30T01:58:59.320014077Z",
                    "perspective_id": "PERSPECTIVE_NTT",
                    "port": 443,
                    "service_name": "HTTP",
                    "source_ip": "1.2.3.4",
                    "tls": {
                        "_encoding": {
                            "ja3s": "DISPLAY_HEX"
                        },
                        "certificates": {
                            "_encoding": {
                                "chain_fps_sha_256": "DISPLAY_HEX",
                                "leaf_fp_sha_256": "DISPLAY_HEX"
                            },
                            "chain": [
                                {
                                    "fingerprint": "23ecb03eec17338c4e33a6b48a41dc3cda12281bbc3ff813c0589d6cc2387522",
                                    "issuer_dn": "C=US, O=Google Trust Services LLC, CN=GTS Root R1",
                                    "subject_dn": "C=US, O=Google Trust Services LLC, CN=GTS CA 1C3"
                                },
                                {
                                    "fingerprint": "3ee0278df71fa3c125c4cd487f01d774694e6fc57e0cd94c24efd769133918e5",
                                    "issuer_dn": "C=BE, O=GlobalSign nv-sa, OU=Root CA, CN=GlobalSign Root CA",
                                    "subject_dn": "C=US, O=Google Trust Services LLC, CN=GTS Root R1"
                                }
                            ],
                            "chain_fps_sha_256": [
                                "23ecb03eec17338c4e33a6b48a41dc3cda12281bbc3ff813c0589d6cc2387522",
                                "3ee0278df71fa3c125c4cd487f01d774694e6fc57e0cd94c24efd769133918e5"
                            ],
                            "leaf_data": {
                                "fingerprint": "5c2d6869e805696c328d7ba5acd7d347b46e1e03d7ed65886bf2df55f41d01fd",
                                "issuer": {
                                    "common_name": [
                                        "GTS CA 1C3"
                                    ],
                                    "country": [
                                        "US"
                                    ],
                                    "organization": [
                                        "Google Trust Services LLC"
                                    ]
                                },
                                "issuer_dn": "C=US, O=Google Trust Services LLC, CN=GTS CA 1C3",
                                "names": [
                                    "*.dns.google.com",
                                    "8.8.4.4",
                                    "8.8.8.8",
                                    "8888.google",
                                    "dns.google",
                                    "dns.google.com",
                                    "dns64.dns.google"
                                ],
                                "pubkey_algorithm": "RSA",
                                "pubkey_bit_size": 2048,
                                "public_key": {
                                    "fingerprint": "32aadd47f0a4b82e0937afda8e6bbff0d42cf50b9c022539d733ec557c215d3f",
                                    "key_algorithm": "RSA",
                                    "rsa": {
                                        "_encoding": {
                                            "exponent": "DISPLAY_BASE64",
                                            "modulus": "DISPLAY_BASE64"
                                        },
                                        "exponent": "AAEAAQ==",
                                        "length": 256,
                                        "modulus": "modulus"
                                    }
                                },
                                "signature": {
                                    "self_signed": false,
                                    "signature_algorithm": "SHA256-RSA"
                                },
                                "subject": {
                                    "common_name": [
                                        "dns.google"
                                    ]
                                },
                                "subject_dn": "CN=dns.google",
                                "tbs_fingerprint": "35b1bccf3f09b949fd27c9d004bcaef9375956d42f59d17f5c076e18d4910645"
                            },
                            "leaf_fp_sha_256": "5c2d6869e805696c328d7ba5acd7d347b46e1e03d7ed65886bf2df55f41d01fd"
                        },
                        "cipher_selected": "SELECTED_CIPHER",
                        "server_key_exchange": {
                            "ec_params": {
                                "named_curve": 23
                            }
                        },
                        "session_ticket": {
                            "length": 221,
                            "lifetime_hint": 100800
                        },
                        "version_selected": "TLSv1_2"
                    },
                    "transport_protocol": "TCP",
                    "truncated": false
                }
            ]
        }
    },
    "DBotScore": {
        "Indicator": "8.8.8.8",
        "Score": 0,
        "Type": "ip",
        "Vendor": "CensysV2"
    },
    "IP": {
        "ASN": 15169,
        "ASOwner": "GOOGLE",
        "Address": "8.8.8.8",
        "Geo": {
            "Country": "United States",
            "Description": "US",
            "Location": "37.751:-97.822"
        }
    }
}
```

#### Human Readable Output

>### Information for IP 8.8.8.8
>|ASN|Routing|Last Updated|Network|Protocols|
>|---|---|---|---|---|
>| 15169 | 8.8.8.0/24 | 2022-08-30T06:39:12.356Z | GOOGLE | {'Port': 53, 'Service Name': 'DNS'},<br/>{'Port': 443, 'Service Name': 'HTTP'},<br/>{'Port': 853, 'Service Name': 'UNKNOWN'} |


### cen-search
***
Returns previews of hosts matching a specified search query, or a list of certificates that match the given query.


#### Base Command

`cen-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query used to search for hosts with matching attributes. Uses the Censys Search Language. | Required | 
| page_size | The maximum number of hits to return in each response (minimum of 0, maximum of 100). Default is 50. (Applies for the host search.) | Optional | 
| limit | The number of results to return. Default is 50. | Optional | 
| index | The index from which to retrieve data. Possible values are: ipv4, certificates. | Required | 
| fields | The fields to return. (Applies for the certificates search). | Optional | 
| page | The page to return. (Applies for the certificates search). Default is 1. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Censys.Search.autonomous_system.asn | Number | The autonomous system number \(ASN\) that the host is in. | 
| Censys.Search.autonomous_system.bgp_prefix | String | The autonomous system's CIDR. | 
| Censys.Search.autonomous_system.country_code | String | he autonomous system's two-letter, ISO 3166-1 alpha-2 country code \(e.g., US, CN, GB, RU\). | 
| Censys.Search.autonomous_system.description | String | A brief description of the autonomous system. | 
| Censys.Search.autonomous_system.name | String | The friendly name of the autonomous system. | 
| Censys.Search.ip | String | The host’s IP address. | 
| Censys.Search.location.continent | String | The continent of the host's detected location \(e.g., North America, Europe, Asia, South America, Africa, Oceania\). | 
| Censys.Search.location.coordinates | Unknown | The estimated coordinates of the host's detected location. | 
| Censys.Search.location.country | String | The country of the host's detected location. | 
| Censys.Search.location.country_code | String | The two-letter ISO 3166-1 alpha-2 country code of the host's detected location \(e.g., US, CN, GB, RU\). | 
| Censys.Search.location.registered_country | String | The host's registered country. | 
| Censys.Search.location.registered_country_code | String | The registered country's two-letter, ISO 3166-1 alpha-2 country code \(e.g., US, CN, GB, RU\). | 
| Censys.Search.location.timezone | String | The IANA time zone database name of the host's detected location. | 
| Censys.Search.services.port | Number | The port the service was reached at. | 
| Censys.Search.services.service_name | String | The name of the service on the port. This is typically the L7 protocol \(e.g., “HTTP”\); however, in the case that a more specific HTTP-based protocol is found \(e.g., Kubernetes or Prometheus\), the field will show that. This field indicates where protocol-specific data will be located. | 
| Censys.Search.services.transport_protocol | String | The transport protocol \(known in OSI model as L4\) used to contact this service \(i.e., UDP or TCP\). | 
| Censys.Search.parsed.fingerprint_sha256 | String | SHA 256 fingerprint. | 
| Censys.Search.parsed.issuer.organization | Unknown | The organization name. | 
| Censys.Search.parsed.names | Unknown | Common names for the entity. | 
| Censys.Search.parsed.subject_dn | String | Distinguished name of the entity that the certificate belongs to. | 
| Censys.Search.parsed.validity.end | Date | Timestamp of when the certificate expires. Time zone is UTC. | 
| Censys.Search.parsed.validity.start | Date | Timestamp of when the certificate is first valid. Time zone is UTC. | 
| Censys.Search.parsed.issuer_dn | String | Distinguished name of the entity that has signed and issued the certificate. | 


#### Command Example
```!cen-search index=certificates query="parsed.issuer.common_name: \"Let's Encrypt\"" limit=1```

#### Context Example
```json
{
    "Censys": {
        "Search": {
            "parsed": {
                "fingerprint_sha256": "f3ade17dffcadd9532aeb2514f10d66e22941393725aa65366ac286df9b1234",
                "issuer": {
                    "organization": [
                        "Let's Encrypt"
                    ]
                },
                "issuer_dn": "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3",
                "names": [
                    "*.45g4rg43g4fr3434g.gb.net",
                    "45g4rg43g4fr3434g.gb.net"
                ],
                "subject_dn": "CN=45g4rg43g4fr3434g.gb.net",
                "validity": {
                    "end": "2021-01-10T14:46:11Z",
                    "start": "2020-10-12T14:46:11Z"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Search results for query "parsed.issuer.common_name: "Let's Encrypt""
>|Issuer|Issuer DN|Names|SHA256|Subject DN|Validity|
>|---|---|---|---|---|---|
>| organization: Let's Encrypt | C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3 | *.45g4rg43g4fr3434g.gb.net,<br/>45g4rg43g4fr3434g.gb.net | f3ade17dffcadd9532aeb2514f10d66e22941393725aa65366ac286df9b442ec | CN=45g4rg43g4fr3434g.gb.net | start: 2020-10-12T14:46:11Z<br/>end: 2021-01-10T14:46:11Z |


## Additional Considerations for this Version
* This version supports API v2 from Censys. 
* Breaking backward compatibility: The Censys v2 integration does not support *websites* searches.


### ip

***
Runs reputation on IPs.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP address or a list of IP addresses to assess reputation. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Censys.IP.services.port | Number   | The port number associated with the service running on the IP. |
| Censys.IP.services.transport_protocol | String | The transport protocol used by the service running on the IP. |
| Censys.IP.services.extended_service_name | String   | The extended name of the service running on the IP. |
| Censys.IP.services.service_name | String | The name of the service running on the IP. |
| Censys.IP.services.certificate | String   | The SSL/TLS certificate associated with the service running on the IP. |
| Censys.IP.labels | String | Labels associated with the IP address (with premium access only). |
| Censys.IP.dns.reverse_dns.names | String | Reverse DNS names associated with the IP address. |
| Censys.IP.autonomous_system.country_code | String | The country code of the autonomous system associated with the IP address. |
| Censys.IP.autonomous_system.description | String | Description of the autonomous system associated with the IP address. |
| Censys.IP.autonomous_system.name | String | Name of the autonomous system associated with the IP address. |
| Censys.IP.autonomous_system.bgp_prefix | String | BGP prefix of the autonomous system associated with the IP address. |
| Censys.IP.autonomous_system.asn | Number | Autonomous System Number (ASN) of the autonomous system associated with the IP address. |
| Censys.IP.ip | String | The IP address. |
| Censys.IP.location.country | String | Country name of the location associated with the IP address. |
| Censys.IP.location.timezone | String | Time zone of the location associated with the IP address. |
| Censys.IP.location.province | String | Province name of the location associated with the IP address. |
| Censys.IP.location.coordinates.latitude | Number | Latitude coordinate of the location associated with the IP address. |
| Censys.IP.location.coordinates.longitude | Number | Longitude coordinate of the location associated with the IP address. |
| Censys.IP.location.continent | String | Continent name of the location associated with the IP address. |
| Censys.IP.location.postal_code | String | Postal code of the location associated with the IP address. |
| Censys.IP.location.city | String | City name of the location associated with the IP address. |
| Censys.IP.location.country_code | String   | Country code of the location associated with the IP address. |
| Censys.IP.last_updated_at | Date | The date and time when the information about the IP address was last updated. |
| IP.Address | unknown | The IP address. | 
| IP.ASN | unknown | The IP ASN. | 
| IP.Geo.Country | unknown | The IP country. | 
| IP.Geo.Location | unknown | The IP location. | 
| IP.UpdatedDate | unknown | The IP last update | 
| IP.Port | unknown | The IP port | 
| DBotScore.Indicator | unknown | The indicator that was tested. | 
| DBotScore.Type | unknown | The indicator type. | 
| DBotScore.Score | Number | The actual score. | 
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. | 
| DBotScore.Vendor | unknown | The vendor used to calculate the score. | 

#### Command example

```!ip ip=8.8.8.8,8.8.4.4```

#### Context Example

```json
{
    "services": [
        {
            "port": 53,
            "transport_protocol": "UDP",
            "extended_service_name": "DNS",
            "service_name": "DNS"
        },
        {
            "certificate": "5a7763efee07b08b18a4af2796bfaac46641a2f15c98e88c3d79fa9a06adfc87",
            "extended_service_name": "HTTPS",
            "port": 443,
            "transport_protocol": "TCP",
            "service_name": "HTTP"
        },
        {
            "service_name": "UNKNOWN",
            "transport_protocol": "QUIC",
            "extended_service_name": "UNKNOWN",
            "port": 443
        },
        {
            "transport_protocol": "TCP",
            "service_name": "UNKNOWN",
            "port": 853,
            "certificate": "5a7763efee07b08b18a4af2796bfaac46641a2f15c98e88c3d79fa9a06adfc87",
            "extended_service_name": "UNKNOWN"
        }
    ],
    "labels": ["database","email","file-sharing","iot","login-page"],
    "dns": {
        "reverse_dns": {
            "names": [
                "dns.google"
            ]
        }
    },
    "autonomous_system": {
        "country_code": "US",
        "description": "GOOGLE",
        "name": "GOOGLE",
        "bgp_prefix": "8.8.8.0/24",
        "asn": 15169
    },
    "ip": "8.8.8.8",
    "location": {
        "country": "United States",
        "timezone": "America/Los_Angeles",
        "province": "California",
        "coordinates": {
            "latitude": 37.4056,
            "longitude": -122.0775
        },
        "continent": "North America",
        "postal_code": "94043",
        "city": "Mountain View",
        "country_code": "US"
    },
    "last_updated_at": "2024-04-07T02:16:23.015Z"
}
```

#### Human Readable Output

>### censys results for IP: 8.8.8.8
>| **Asn** | **Geo Country** | **Geo Latitude** | **Geo Longitude** | **Ip** | **Port** | **Reputation** | **Updated** |
>| --- | --- | --- | --- | --- | --- | --- |  --- |
>| 15169 | United States | 37.4056 | -122.0775 | 8.8.8.8 | 53, 443, 443, 853 | 0 | 2024-04-14T08:03:28.159Z |


### domain

***
Return all related IPs as relationships.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | Domain to check. | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Censys.Domain.location.postal_code | String | The postal code of the location associated with the domain. |
| Censys.Domain.location.province | String | The province name of the location associated with the domain. |
| Censys.Domain.location.country_code | String | The country code of the location associated with the domain. |
| Censys.Domain.location.timezone | String | The time zone of the location associated with the domain. |
| Censys.Domain.location.country | String | The country name of the location associated with the domain. |
| Censys.Domain.location.coordinates.longitude | Number | The longitude coordinate of the location associated with the domain. |
| Censys.Domain.location.coordinates.latitude | Number | The latitude coordinate of the location associated with the domain. |
| Censys.Domain.location.continent | String | The continent name of the location associated with the domain. |
| Censys.Domain.location.city | String | The city name of the location associated with the domain. |
| Censys.Domain.autonomous_system.country_code | String | The country code of the autonomous system associated with the domain. |
| Censys.Domain.autonomous_system.asn | Number | The Autonomous System Number (ASN) associated with the domain. |
| Censys.Domain.autonomous_system.name | String | The name of the autonomous system associated with the domain. |
| Censys.Domain.autonomous_system.bgp_prefix | String | The BGP prefix of the autonomous system associated with the domain. |
| Censys.Domain.autonomous_system.description | String | The description of the autonomous system associated with the domain. |
| Censys.Domain.services.transport_protocol | String | The transport protocol used by the service associated with the domain. |
| Censys.Domain.services.extended_service_name | String | The extended name of the service associated with the domain. |
| Censys.Domain.services.port | Number | The port number associated with the service associated with the domain. |
| Censys.Domain.services.service_name | String | The name of the service associated with the domain. |
| Censys.Domain.services.certificate | String | The SSL/TLS certificate associated with the service associated with the domain. |
| Censys.Domain.last_updated_at | Date | The date and time when the information about the domain was last updated. |
| Censys.Domain.ip | String | The IP address associated with the domain. |
| Censys.Domain.dns.reverse_dns.names | String | The reverse DNS names associated with the domain. |
| Domain.Name | string. | The domain. | 
| Domain.Relationships.EntityA | string. | The domain name. | 
| Domain.Relationships.EntityAType | string. | The entity type. | 
| Domain.Relationships.EntityB | string. | The entity B. | 
| Domain.Relationships.EntityBType | string. | The entity B type. | 
| Domain.Relationships.Relationship | string. | The relationship type. | 
| DBotScore.Indicator | unknown | The indicator that was tested. | 
| DBotScore.Type | unknown | The indicator type.| 
| DBotScore.Score | unknown | The actual score. | 
| DBotScore.Vendor | unknown | The vendor used to calculate the score. | 

#### Command example

```!domain domain=amazon.com,facebook.com```

#### Context Example

```json
{
    "code": 200,
    "status": "OK",
    "result": {
      "query": "dns.names=amazon.com",
      "total": 3,
      "duration": 239,
      "hits": [
        {
          "location": {
            "province": "Virginia",
            "country": "United States",
            "coordinates": {
              "longitude": -77.48749,
              "latitude": 39.04372
            },
            "timezone": "America/New_York",
            "country_code": "US",
            "continent": "North America",
            "postal_code": "20147",
            "city": "Ashburn"
          },
          "autonomous_system": {
            "description": "AMAZON-02",
            "bgp_prefix": "1.1.1.1",
            "name": "AMAZON-02",
            "country_code": "US",
            "asn": 16509
          },
          "services": [
            {
              "port": 80,
              "transport_protocol": "TCP",
              "service_name": "HTTP",
              "extended_service_name": "HTTP"
            },
            {
              "transport_protocol": "TCP",
              "certificate": "XXXXXXX",
              "extended_service_name": "HTTPS",
              "service_name": "HTTP",
              "port": 443
            }
          ],
          "last_updated_at": "2024-04-06T16:57:13.170Z",
          "ip": "1.1.1.1."
        },
        {
          "ip": "1.1.1.1",
          "services": [
            {
              "port": 80,
              "transport_protocol": "TCP",
              "service_name": "HTTP",
              "extended_service_name": "HTTP"
            },
            {
              "port": 443,
              "transport_protocol": "TCP",
              "extended_service_name": "HTTPS",
              "service_name": "HTTP",
              "certificate": "XXXXXXX"
            }
          ],
          "dns": {
            "reverse_dns": {
              "names": [
                "s3-console-us-standard.console.aws.amazon.com"
              ]
            }
          },
          "location": {
            "province": "Virginia",
            "postal_code": "20147",
            "country": "United States",
            "timezone": "America/New_York",
            "continent": "North America",
            "city": "Ashburn",
            "country_code": "US",
            "coordinates": {
              "latitude": 39.04372,
              "longitude": -77.48749
            }
          },
          "autonomous_system": {
            "country_code": "US",
            "bgp_prefix": "1.1.1.1",
            "asn": 16509,
            "description": "AMAZON-02",
            "name": "AMAZON-02"
          },
          "last_updated_at": "2024-04-06T16:57:13.171Z"
        },
        {
          "location": {
            "postal_code": "20147",
            "province": "Virginia",
            "country_code": "US",
            "timezone": "America/New_York",
            "country": "United States",
            "coordinates": {
              "longitude": -77.48749,
              "latitude": 39.04372
            },
            "continent": "North America",
            "city": "Ashburn"
          },
          "last_updated_at": "2024-04-06T16:57:13.170Z",
          "autonomous_system": {
            "country_code": "US",
            "asn": 16509,
            "name": "AMAZON-02",
            "bgp_prefix": "1.1.1.1",
            "description": "AMAZON-02"
          },
          "services": [
            {
              "transport_protocol": "TCP",
              "extended_service_name": "HTTP",
              "port": 80,
              "service_name": "HTTP"
            },
            {
              "extended_service_name": "HTTPS",
              "transport_protocol": "TCP",
              "certificate": "XXXXXX",
              "service_name": "HTTP",
              "port": 443
            }
          ],
          "ip": "1.1.1.1"
        }
      ],
      "links": {
        "next": "",
        "prev": ""
      }
    }
}
```

#### Human Readable Output

| **Domain** |
| --- |
| amazon.com |