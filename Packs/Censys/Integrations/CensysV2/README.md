Censys is a search engine that allows computer scientists to ask questions about the devices and networks that compose the Internet. Driven by Internet-wide scanning, Censys lets researchers find specific hosts and create aggregate reports on how devices, websites, and certificates are configured and deployed.

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
```!censys-host-view query=8.8.8.8```

#### Context Example
```json
{
    "Censys": {
        "View": {
            "autonomous_system": {
                "asn": 15169,
                "bgp_prefix": "1.2.3.4/24",
                "country_code": "US",
                "description": "GOOGLE",
                "name": "GOOGLE"
            },
            "autonomous_system_updated_at": "2021-11-21T12:57:11.200575Z",
            "dns": {
                "names": [
                    "wiki.leadership.com.",
                    "uuu.mkppy.site.",
                    "hisports.club.",
                    "test.com.",
                    "roidgames.de.",
                    "svhasso.duckdns.org."
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
                    "resolved_at": "2021-11-19T14:46:47.044806032Z"
                }
            },
            "ip": "8.8.8.8",
            "last_updated_at": "2021-12-05T08:04:21.488Z",
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
                "timezone": "America/Chicago"
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
                    "observed_at": "2021-12-05T08:04:21.245587493Z",
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
                    "banner": "Some banner",
                    "banner_hex": "485454502f312e312033303220466f756e640a5365727665723a2048545450207365727665722028756e6b6e6f776e290a436f6e74656e742d4c656e6774683a203231360a582d436f6e74656e742d547970652d4f7074696f6e733a206e6f736e6966660a436f6e74656e742d547970653a20746578742f68746d6c3b20636861727365743d5554462d380a446174653a203c52454441435445443e0a582d5873732d50726f74656374696f6e3a20300a4163636573732d436f6e74726f6c2d416c6c6f772d4f726967696e3a202a0a4c6f636174696f6e3a2068747470733a2f2f646e732e676f6f676c652f0a416c742d5376633a2068333d223a343433223b206d613d323539323030302c68332d32393d223a343433223b206d613d323539323030302c68332d513035303d223a343433223b206d613d323539323030302c68332d513034363d223a343433223b206d613d323539323030302c68332d513034333d223a343433223b206d613d323539323030302c717569633d223a343433223b206d613d323539323030303b20763d2234362c3433220a582d4672616d652d4f7074696f6e733a2053414d454f524947494e",
                    "certificate": "bb9648a9935fe0d07ba4e1c341286382d54a75e79ac1564988bd78e123456",
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
                            "body_hash": "sha1:1fd84b37b709256752fe1f865f86b5bec05c1234",
                            "body_size": 216,
                            "headers": {
                                "Access_Control_Allow_Origin": [
                                    "*"
                                ],
                                "Alt_Svc": [
                                    "some text"
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
                    "observed_at": "2021-12-04T23:05:35.556566229Z",
                    "perspective_id": "PERSPECTIVE_HE",
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
                                        "modulus": "longString"
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
                        "cipher_selected": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
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
>| 15169 | 8.8.8.0/24 | 2021-12-05T08:04:21.488Z | GOOGLE | {'Port': 53, 'Service Name': 'DNS'},<br/>{'Port': 443, 'Service Name': 'HTTP'} |


### censys-hosts-search
***
Return previews of hosts matching a specified search query.


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
```!censys-hosts-search query="services.service_name:HTTP" limit=1```

#### Context Example
```json
{
    "Censys": {
        "HostSearch": {
            "autonomous_system": {
                "asn": 13335,
                "bgp_prefix": "1.0.0.0/24",
                "country_code": "US",
                "description": "CLOUDFLARENET",
                "name": "CLOUDFLARENET"
            },
            "ip": "1.0.0.0",
            "location": {
                "continent": "Oceania",
                "coordinates": {
                    "latitude": -33.494,
                    "longitude": 143.2104
                },
                "country": "Australia",
                "country_code": "AU",
                "registered_country": "Australia",
                "registered_country_code": "AU",
                "timezone": "Australia/Sydney"
            },
            "services": [
                {
                    "port": 80,
                    "service_name": "HTTP",
                    "transport_protocol": "TCP"
                },
                {
                    "port": 443,
                    "service_name": "HTTP",
                    "transport_protocol": "TCP"
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Search results for query "services.service_name:HTTP"
>|IP|Name|Description|ASN|Location Country code|Registered Country Code|Services|
>|---|---|---|---|---|---|---|
>| 1.0.0.0 | CLOUDFLARENET | CLOUDFLARENET | 13335 | AU | AU | {'port': 80, 'service_name': 'HTTP', 'transport_protocol': 'TCP'},<br/>{'port': 443, 'service_name': 'HTTP', 'transport_protocol': 'TCP'} |


### censys-certificates-search
***
Returns a list of certificates that match the given query.


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
| Censys.CertificateSearch.parsed.issuer.organization | Unknown | The organization name. | 
| Censys.CertificateSearch.parsed.issuer_dn | String | Distinguished name of the entity that has signed and issued the certificate. | 
| Censys.CertificateSearch.parsed.names | Unknown | Common names for the entity. | 
| Censys.CertificateSearch.parsed.subject_dn | String | Distinguished name of the entity that the certificate belongs to. | 
| Censys.CertificateSearch.parsed.validity.end | String | Validity end date. | 
| Censys.CertificateSearch.parsed.validity.start | String | Validity start date. | 


#### Command Example
```!censys-certificates-search query="parsed.issuer.common_name: \"Let's Encrypt\"" limit=1```

#### Context Example
```json
{
    "Censys": {
        "CertificateSearch": {
            "parsed": {
                "fingerprint_sha256": "f3ade17dffcadd9532aeb2514f10d66e22941393725aa65366ac286df9b442ec",
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
```!censys-certificate-view query=9d3b51a6b80daf76e074730f19dc01e643ca0c3127d8f48be64cf3302f661234```

#### Context Example
```json
{
    "Censys": {
        "CertificateView": {
            "ct": {
                "digicert_ct1": {
                    "added_to_ct_at": "2015-09-29T19:55:46.232Z",
                    "ct_to_censys_at": "2018-07-30T04:49:40.404877527Z",
                    "index": 165790
                },
                "google_aviator": {
                    "added_to_ct_at": "1970-01-01T00:00:00Z",
                    "ct_to_censys_at": "1970-01-01T00:00:00Z",
                    "index": 8713649
                }
            },
            "fingerprint_sha256": "9d3b51a6b80daf76e074730f19dc01e643ca0c3127d8f48be64cf3302f661234",
            "metadata": {
                "added_at": "1970-01-01T00:00:00Z",
                "parse_status": "success",
                "parse_version": 1,
                "post_processed": true,
                "post_processed_at": "2021-06-22T01:40:32Z",
                "seen_in_scan": true,
                "source": "scan",
                "updated_at": "2021-06-22T03:28:34Z"
            },
            "parent_spki_subject_fingerprint": "ec0c72ce7689150e4f62d04f51f0f19713f77cf27ff43cab4035e9e54e846aa9",
            "parsed": {
                "extensions": {
                    "authority_info_access": {
                        "issuer_urls": [
                            "http://pki.google.com/GIAG2.crt"
                        ],
                        "ocsp_urls": [
                            "http://clients1.google.com/ocsp"
                        ]
                    },
                    "authority_key_id": "4add06161bbcf668b576f581b6bb621aba5a812f",
                    "basic_constraints": {
                        "is_ca": false
                    },
                    "certificate_policies": [
                        {
                            "id": "1.2.3.4.4.1.11129.2.5.1"
                        },
                        {
                            "id": "5.6.7.8.2.2"
                        }
                    ],
                    "crl_distribution_points": [
                        "http://pki.google.com/GIAG2.crl"
                    ],
                    "extended_key_usage": {
                        "client_auth": true,
                        "server_auth": true
                    },
                    "key_usage": {
                        "digital_signature": true,
                        "value": 1
                    },
                    "subject_alt_name": {
                        "dns_names": [
                            "*.google.com",
                            "*.android.com",
                            "*.appengine.google.com",
                            "*.cloud.google.com",
                            "*.google-analytics.com",
                            "*.google.ca",
                            "*.google.cl",
                            "*.google.co.in",
                            "*.google.co.jp",
                            "*.google.co.uk",
                            "*.google.com.ar",
                            "*.google.com.au",
                            "*.google.com.br",
                            "*.google.com.co",
                            "*.google.com.mx",
                            "*.google.com.tr",
                            "*.google.com.vn",
                            "*.google.de",
                            "*.google.es",
                            "*.google.fr",
                            "*.google.hu",
                            "*.google.it",
                            "*.google.nl",
                            "*.google.pl",
                            "*.google.pt",
                            "*.googleadapis.com",
                            "*.googleapis.cn",
                            "*.googlecommerce.com",
                            "*.googlevideo.com",
                            "*.gstatic.cn",
                            "*.gstatic.com",
                            "*.gvt1.com",
                            "*.gvt2.com",
                            "*.metric.gstatic.com",
                            "*.urchin.com",
                            "*.url.google.com",
                            "*.youtube-nocookie.com",
                            "*.youtube.com",
                            "*.youtubeeducation.com",
                            "*.ytimg.com",
                            "android.com",
                            "g.co",
                            "goo.gl",
                            "google-analytics.com",
                            "google.com",
                            "googlecommerce.com",
                            "urchin.com",
                            "youtu.be",
                            "youtube.com",
                            "youtubeeducation.com"
                        ]
                    },
                    "subject_key_id": "19c6b145efc879529b4a57b15e0d543b011dce35"
                },
                "fingerprint_md5": "0f263d5e56288c37ade29f7b9977f38d",
                "fingerprint_sha1": "8740f09afc54752b26b295cdc6393c6b8ffd9e6a",
                "fingerprint_sha256": "9d3b51a6b80daf76e074730f19dc01e643ca0c3127d8f48be64cf3302f661234",
                "issuer": {
                    "common_name": [
                        "Google Internet Authority G2"
                    ],
                    "country": [
                        "US"
                    ],
                    "organization": [
                        "Google Inc"
                    ]
                },
                "issuer_dn": "C=US, O=Google Inc, CN=Google Internet Authority G2",
                "names": [
                    "*.android.com",
                    "*.appengine.google.com",
                    "*.cloud.google.com",
                    "*.google-analytics.com",
                    "*.google.ca",
                    "*.google.cl",
                    "*.google.co.in",
                    "*.google.co.jp",
                    "*.google.co.uk",
                    "*.google.com",
                    "*.google.com.ar",
                    "*.google.com.au",
                    "*.google.com.br",
                    "*.google.com.co",
                    "*.google.com.mx",
                    "*.google.com.tr",
                    "*.google.com.vn",
                    "*.google.de",
                    "*.google.es",
                    "*.google.fr",
                    "*.google.hu",
                    "*.google.it",
                    "*.google.nl",
                    "*.google.pl",
                    "*.google.pt",
                    "*.googleadapis.com",
                    "*.googleapis.cn",
                    "*.googlecommerce.com",
                    "*.googlevideo.com",
                    "*.gstatic.cn",
                    "*.gstatic.com",
                    "*.gvt1.com",
                    "*.gvt2.com",
                    "*.metric.gstatic.com",
                    "*.urchin.com",
                    "*.url.google.com",
                    "*.youtube-nocookie.com",
                    "*.youtube.com",
                    "*.youtubeeducation.com",
                    "*.ytimg.com",
                    "android.com",
                    "g.co",
                    "goo.gl",
                    "google-analytics.com",
                    "google.com",
                    "googlecommerce.com",
                    "urchin.com",
                    "youtu.be",
                    "youtube.com",
                    "youtubeeducation.com"
                ],
                "redacted": false,
                "serial_number": "5878999135690490607",
                "signature": {
                    "self_signed": false,
                    "signature_algorithm": {
                        "name": "SHA256-RSA",
                        "oid": "1.2.840.113549.1.1.11"
                    },
                    "valid": false,
                    "value": "longString"
                },
                "signature_algorithm": {
                    "name": "SHA256-RSA",
                    "oid": "1.2.840.113549.1.1.11"
                },
                "spki_subject_fingerprint": "5eb06b1c29ced84998d3d35a80fa17d3d39e4de96d25539485aecd6360f618dc",
                "subject": {
                    "common_name": [
                        "*.google.com"
                    ],
                    "country": [
                        "US"
                    ],
                    "locality": [
                        "Mountain View"
                    ],
                    "organization": [
                        "Google Inc"
                    ],
                    "province": [
                        "California"
                    ]
                },
                "subject_dn": "C=US, ST=California, L=Mountain View, O=Google Inc, CN=*.google.com",
                "subject_key_info": {
                    "ecdsa_public_key": {
                        "b": "WsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848Pi1234567",
                        "curve": "P-256",
                        "gx": "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5Rd1234567",
                        "gy": "T+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaD1234567",
                        "length": 256,
                        "n": "/////wAAAAD//////////7zm+q2nF56E87nKwv1234567",
                        "p": "/////wAAAAEAAAAAAAAAAAAAAAD////////////12345",
                        "pub": "BPaA0OXDoRYvJCAXYXat17qSfAzstSRTv6hKFsn+ViGbHsKzG88q4w1ftFxHXtx5clv1eImjsqduyUDVZ1234567",
                        "x": "9oDQ5cOhFi8kIBdhdq3XupJ8DOy1JFO/qEoW1234567",
                        "y": "HsKzG88q4w1ftFxHXtx5clv1eImjsqduyUDVZ123456"
                    },
                    "fingerprint_sha256": "3d4a4bd778be7965e90a13ac361e1ed7836d24c15cd5c093f9cc7e7857f51234",
                    "key_algorithm": {
                        "name": "ECDSA"
                    }
                },
                "tbs_fingerprint": "1661b59eb7d8cda44f800fabc9ef69ba01506309eedf027f2270105afd161234",
                "tbs_noct_fingerprint": "1661b59eb7d8cda44f800fabc9ef69ba01506309eedf027f2270105afd161234",
                "validation_level": "OV",
                "validity": {
                    "end": "2015-12-28T00:00:00Z",
                    "length": 7708840,
                    "start": "2015-09-29T18:39:20Z"
                },
                "version": 3
            },
            "precert": false,
            "raw": "MIIGzzCCBbegAwIBAgIIUZZmkM2pAu8wDQYJKoZIhvcNAQELBQAwSTELMAkGA1UEBhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRlcm5ldCBBdXRob3JpdHkgRzIwHhcNMTUwOTI5MTgzOTIwWhcNMTUxMjI4MDAwMDAwWjBmMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEVMBMGA1UEAwwMKi5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9oDQ5cOhFi8kIBdhdq3XupJ8DOy1JFO/qEoWyf5WIZsewrMbzyrjDV+0XEde3HlyW/V4iaOyp27JQNVn5m/Od6OCBGcwggRjMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjCCAyYGA1UdEQSCAx0wggMZggwqLmdvb2dsZS5jb22CDSouYW5kcm9pZC5jb22CFiouYXBwZW5naW5lLmdvb2dsZS5jb22CEiouY2xvdWQuZ29vZ2xlLmNvbYIWKi5nb29nbGUtYW5hbHl0aWNzLmNvbYILKi5nb29nbGUuY2GCCyouZ29vZ2xlLmNsgg4qLmdvb2dsZS5jby5pboIOKi5nb29nbGUuY28uanCCDiouZ29vZ2xlLmNvLnVrgg8qLmdvb2dsZS5jb20uYXKCDyouZ29vZ2xlLmNvbS5hdYIPKi5nb29nbGUuY29tLmJygg8qLmdvb2dsZS5jb20uY2+CDyouZ29vZ2xlLmNvbS5teIIPKi5nb29nbGUuY29tLnRygg8qLmdvb2dsZS5jb20udm6CCyouZ29vZ2xlLmRlggsqLmdvb2dsZS5lc4ILKi5nb29nbGUuZnKCCyouZ29vZ2xlLmh1ggsqLmdvb2dsZS5pdIILKi5nb29nbGUubmyCCyouZ29vZ2xlLnBsggsqLmdvb2dsZS5wdIISKi5nb29nbGVhZGFwaXMuY29tgg8qLmdvb2dsZWFwaXMuY26CFCouZ29vZ2xlY29tbWVyY2UuY29tghEqLmdvb2dsZXZpZGVvLmNvbYIMKi5nc3RhdGljLmNugg0qLmdzdGF0aWMuY29tggoqLmd2dDEuY29tggoqLmd2dDIuY29tghQqLm1ldHJpYy5nc3RhdGljLmNvbYIMKi51cmNoaW4uY29tghAqLnVybC5nb29nbGUuY29tghYqLnlvdXR1YmUtbm9jb29raWUuY29tgg0qLnlvdXR1YmUuY29tghYqLnlvdXR1YmVlZHVjYXRpb24uY29tggsqLnl0aW1nLmNvbYILYW5kcm9pZC5jb22CBGcuY2+CBmdvby5nbIIUZ29vZ2xlLWFuYWx5dGljcy5jb22CCmdvb2dsZS5jb22CEmdvb2dsZWNvbW1lcmNlLmNvbYIKdXJjaGluLmNvbYIIeW91dHUuYmWCC3lvdXR1YmUuY29tghR5b3V0dWJlZWR1Y2F0aW9uLmNvbTALBgNVHQ8EBAMCB4AwaAYIKwYBBQUHAQEEXDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3J0MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9vY3NwMB0GA1UdDgQWBBQZxrFF78h5UptKV7FeDVQ7AR3ONTAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEvMCEGA1UdIAQaMBgwDAYKKwYBBAHWeQIFATAIBgZngQwBAgIwMAYDVR0fBCkwJzAloCOgIYYfaHR0cDovL3BraS5nb29nbGUuY29tL0dJQUcyLmNybDANBgkqhkiG9w0BAQsFAAOCAQEAHjY1fHmswcmd3sMp0GoWlbLoLMbuiE1qaZ4DUhn8gE3z0JDn6RDYjZ8qOqMA3/Fqcywzd1vKB0snm2JRkk9ZfBYNO1aIsXpSXaCBjtFmVPeZarLIFietWe6bS+lLbC4FhzU5/bg7KAy7zPZHuh1E+ys76v4O/Jui5iWO+Amkywu+xU4J3SEjbKEJYubXsa5CMovNwl+le2UPiu/xqu+QchCYVj6KQGVnRiZ0s5MY86bKVPxlHRXKjuyt/2FISp48sHgQDmq5bZ1iB5h1Lc+DvdOyvmm738IsDoev8QziMF2FXGyaETPm/CB2AfE58Mj9s9rl0hNx7/m+Zt557crvag==",
            "tags": [
                "was-trusted",
                "expired",
                "ct",
                "ov"
            ],
            "validation": {
                "apple": {
                    "blacklisted": false,
                    "had_trusted_path": true,
                    "in_revocation_set": false,
                    "parents": [
                        "c3f697a92a293d86f9a3ee7ccb970e20e0050b8728cc83ed1b996ce9005d4c36",
                        "9f630426df1d8abfd80ace98871ba833ab9742cb34838de2b5285ed54c0c7dcc",
                        "a4124fdaf9cac7baee1cab32e3225d746500c09f3cf3ebb253ef3fbb088afd34",
                        "44336eb05c6c783dc177217a9f6fef75f4524e98045b390803ae9de69eb41234"
                    ],
                    "paths": [
                        [
                            "9d3b51a6b80daf76e074730f19dc01e643ca0c3127d8f48be64cf3302f661234",
                            "a4124fdaf9cac7baee1cab32e3225d746500c09f3cf3ebb253ef3fbb088afd34",
                            "ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a"
                        ],
                        [
                            "9d3b51a6b80daf76e074730f19dc01e643ca0c3127d8f48be64cf3302f661234",
                            "44336eb05c6c783dc177217a9f6fef75f4524e98045b390803ae9de69eb41234",
                            "ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a"
                        ]
                    ],
                    "trusted_path": false,
                    "type": "leaf",
                    "valid": false,
                    "was_valid": true,
                    "whitelisted": false
                },
                "google_ct_primary": {
                    "blacklisted": false,
                    "had_trusted_path": true,
                    "in_revocation_set": false,
                    "parents": [
                        "c3f697a92a293d86f9a3ee7ccb970e20e0050b8728cc83ed1b996ce9005d4c36",
                        "9f630426df1d8abfd80ace98871ba833ab9742cb34838de2b5285ed54c0c7dcc",
                        "a4124fdaf9cac7baee1cab32e3225d746500c09f3cf3ebb253ef3fbb088afd34",
                        "44336eb05c6c783dc177217a9f6fef75f4524e98045b390803ae9de69eb41234"
                    ],
                    "paths": [
                        [
                            "9d3b51a6b80daf76e074730f19dc01e643ca0c3127d8f48be64cf3302f661234",
                            "a4124fdaf9cac7baee1cab32e3225d746500c09f3cf3ebb253ef3fbb088afd34",
                            "ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a"
                        ],
                        [
                            "9d3b51a6b80daf76e074730f19dc01e643ca0c3127d8f48be64cf3302f661234",
                            "44336eb05c6c783dc177217a9f6fef75f4524e98045b390803ae9de69eb41234",
                            "ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a"
                        ]
                    ],
                    "trusted_path": false,
                    "type": "leaf",
                    "valid": false,
                    "was_valid": true,
                    "whitelisted": false
                },
                "microsoft": {
                    "blacklisted": false,
                    "had_trusted_path": true,
                    "in_revocation_set": false,
                    "parents": [
                        "c3f697a92a293d86f9a3ee7ccb970e20e0050b8728cc83ed1b996ce9005d4c36",
                        "9f630426df1d8abfd80ace98871ba833ab9742cb34838de2b5285ed54c0c7dcc",
                        "a4124fdaf9cac7baee1cab32e3225d746500c09f3cf3ebb253ef3fbb088afd34",
                        "44336eb05c6c783dc177217a9f6fef75f4524e98045b390803ae9de69eb41234"
                    ],
                    "paths": [
                        [
                            "9d3b51a6b80daf76e074730f19dc01e643ca0c3127d8f48be64cf3302f661234",
                            "a4124fdaf9cac7baee1cab32e3225d746500c09f3cf3ebb253ef3fbb088afd34",
                            "ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a"
                        ],
                        [
                            "9d3b51a6b80daf76e074730f19dc01e643ca0c3127d8f48be64cf3302f661234",
                            "44336eb05c6c783dc177217a9f6fef75f4524e98045b390803ae9de69eb41234",
                            "ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a"
                        ]
                    ],
                    "trusted_path": false,
                    "type": "leaf",
                    "valid": false,
                    "was_valid": true,
                    "whitelisted": false
                },
                "nss": {
                    "blacklisted": false,
                    "had_trusted_path": false,
                    "in_revocation_set": false,
                    "paths": [],
                    "trusted_path": false,
                    "type": "unknown",
                    "valid": false,
                    "was_valid": false,
                    "whitelisted": false
                },
                "revoked": false
            },
            "zlint": {
                "errors_present": false,
                "fatals_present": false,
                "lints": {
                    "n_subject_common_name_included": true,
                    "w_ext_key_usage_not_critical": true
                },
                "notices_present": true,
                "version": 3,
                "warnings_present": true
            }
        }
    }
}
```

#### Human Readable Output

>### Information for certificate 
>|Added|SHA 256|Source|Tags|Updated|
>|---|---|---|---|---|
>| 1970-01-01T00:00:00Z | 9d3b51a6b80daf76e074730f19dc01e643ca0c3127d8f48be64cf3302f661234 | scan | was-trusted,<br/>expired,<br/>ct,<br/>ov | 2021-06-22T03:28:34Z |


## Breaking changes from the previous version of this integration - Censys
This is a new version, the old version of the API is deprecated (by Censys).
The following sections list the changes in this version.

### Commands
#### The following commands were removed in this version:
* *cen-view* - this command was replaced by:
    - censys-host-view
    - censys-certificate-view
* *cen-search* - this command was replaced by:
    - censys-certificates-search
    - censys-hosts-search

## Additional Considerations for this version
* This API no longer supports *websites* searches.
* The *limit* argument was added to all commands.
