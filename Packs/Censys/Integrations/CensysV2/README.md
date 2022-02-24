Censys is a search engine that allows computer scientists to ask questions about the devices and networks that compose the internet. Driven by internet-wide scanning, Censys lets researchers find specific hosts and create aggregate reports on how devices, and certificates are configured and deployed.
This integration was integrated and tested with version 2.0 of Censys.

Some changes have been made that might affect your existing content. 
If you are upgrading from a previous of this integration, see [Breaking Changes](#additional-considerations-for-this-version).

## Configure Censys v2 on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Censys v2.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | App ID | True |
    | Secret | True |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
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
| Censys.View.services.service_name | String | The name of the service on the port. This is typically the L7 protocol \(e.g., “HTTP”\); however, in case a more specific HTTP-based protocol is found \(e.g., Kubernetes or Prometheus\), the field will show that. This field indicates where protocol-specific data will be located. | 
| Censys.View.services.source_ip | String | The IP address from which Censys scanned the service. | 
| Censys.View.services.transport_protocol | String | The transport protocol \(known in OSI model as L4\) used to contact this service \(i.e., UDP or TCP\). | 
| Censys.View.services.banner | String | The banner as a part of the protocol scan. That field will be nested in the protocol-specific data under the service_name field. | 
| Censys.View.services.tls.certificates | Unknown | A subset of the parsed details of the certificate, including the issuer, subject, fingerprint, names, public keys, and signature | 
| Censys.View.services.tls.session_ticket | Unknown | Details about the session ticket provided by the server at the end of the TLS handshake. | 
| Censys.View.ct | Unknown | When a certificate was added to a CT log. | 
| Censys.View.fingerprint_sha256 | String | The SHA2-256 digest over the DER encoding of the certificate. | 
| Censys.View.metadata | Unknown | Whether the certificate was \(ever\) seen during a Censys scan of the internet. | 
| Censys.View.parent_spki_subject_fingerprint | String | Parent simple public key infrastructure (SPKI) subject fingerprint. | 
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
| Censys.View.parsed.validity.end | Date | Timestamp of when certificate expires. Timezone is UTC. | 
| Censys.View.parsed.validity.length | Number | The length of time, in seconds, that the certificate is valid. | 
| Censys.View.parsed.validity.start | Date | Timestamp of when certificate is first valid. Timezone is UTC. | 
| Censys.View.parsed.version | Number | The x.509 certificate version number. | 
| Censys.View.precert | Boolean | Whether the certificate is pre-cert. | 
| Censys.View.raw | String | The raw certificate. | 
| Censys.View.tags | String | Tags applied to the certificate. | 
| Censys.View.validation | Unknown | Whether the certificate is trusted by modern web browsers \(Mozilla NSS, Microsoft, and Apple\). | 
| Censys.View.zlint | Unknown | Whether the certificate has any zlint errors. | 


#### Command Example
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
            "autonomous_system_updated_at": "2021-12-06T16:40:32.741814Z",
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
                    "resolved_at": "2021-12-06T20:10:26.799869407Z"
                }
            },
            "ip": "8.8.8.8",
            "last_updated_at": "2021-12-07T10:00:28.435Z",
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
            "location_updated_at": "2021-11-26T17:14:23.038540Z",
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
                    "observed_at": "2021-12-07T10:00:28.379350407Z",
                    "perspective_id": "PERSPECTIVE_NTT",
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
                    "banner_hex": "485454502f312e312033303220466f756e640a5365727665723a2048545450207365727665722028756e6b6e6f776e290a436f6e74656e742d4c656e6774683a203231360a582d436f6e74656e742d547970652d4f7074696f6e733a206e6f736e6966660a436f6e74656e742d547970653a20746578742f68746d6c3b20636861727365743d5554462d380a446174653a203c52454441435445443e0a582d5873732d50726f74656374696f6e3a20300a4163636573732d436f6e74726f6c2d416c6c6f772d4f726967696e3a202a0a4c6f636174696f6e3a2068747470733a2f2f646e732e676f6f676c652f0a416c742d5376633a2068333d223a343433223b206d613d323539323030302c68332d32393d223a343433223b206d613d323539323030302c68332d513035303d223a343433223b206d613d323539323030302c68332d513034363d223a343433223b206d613d323539323030302c68332d513034333d223a343433223b206d613d323539323030302c717569633d223a343433223b206d613d323539323030303b20763d2234362c3433220a582d4672616d652d4f7074696f6e733a2053414d454f524947494e",
                    "certificate": "bb9648a9935fe0d07ba4e1c341286382d54a75e79ac1564988bd78e201234567",
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
                            "body": "<HTML><HEAD><meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n<TITLE>302 Moved</TITLE></HEAD><BODY>\n<H1>302 Moved</H1>\nThe document has moved\n<A HREF=\"https://dns.google/\">here</A>.\r\n</BODY></HTML>\r\n",
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
                        }
                    },
                    "observed_at": "2021-12-07T06:23:41.581346512Z",
                    "perspective_id": "PERSPECTIVE_TATA",
                    "port": 443,
                    "service_name": "HTTP",
                    "source_ip": "1.2.3.4",
                    "tls": {
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
                                "fingerprint": "bb9648a9935fe0d07ba4e1c341286382d54a75e79ac1564988bd78e20cb81234",
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
                                    "fingerprint": "eb975485cb4281ae832fb5ebd210c58be57c57fddab0631b30eec783730a8536",
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
                                "tbs_fingerprint": "7f2e4098c54f11e6d1f1ea679716525852f819b12fdd443f4074f862ff75911e"
                            },
                            "leaf_fp_sha_256": "bb9648a9935fe0d07ba4e1c341286382d54a75e79ac1564988bd78e20cb8103a"
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
    }
}
```

#### Human Readable Output

>### Information for IP 8.8.8.8
>|ASN|Bgp Prefix|Last Updated|Name|Service|
>|---|---|---|---|---|
>| 15169 | 8.8.8.0/24 | 2021-12-07T10:00:28.435Z | GOOGLE | {'Port': 53, 'Service Name': 'DNS'},<br/>{'Port': 443, 'Service Name': 'HTTP'} |


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
| Censys.Search.parsed.validity.end | Date | Timestamp of when the certificate expires. Timezone is UTC. | 
| Censys.Search.parsed.validity.start | Date | Timestamp of when the certificate is first valid. Timezone is UTC. | 
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
>|Issuer|Issuer dn|Names|SHA256|Subject dn|Validity|
>|---|---|---|---|---|---|
>| organization: Let's Encrypt | C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3 | *.45g4rg43g4fr3434g.gb.net,<br/>45g4rg43g4fr3434g.gb.net | f3ade17dffcadd9532aeb2514f10d66e22941393725aa65366ac286df9b442ec | CN=45g4rg43g4fr3434g.gb.net | start: 2020-10-12T14:46:11Z<br/>end: 2021-01-10T14:46:11Z |


## Additional Considerations for this Version
* This version supports API v2 from Censys. 
* Breaking backward compatibility: The Censys v2 integration does not support *websites* searches.
