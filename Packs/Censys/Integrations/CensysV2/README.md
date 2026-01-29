Censys is a search engine that allows computer scientists to ask questions about the devices and networks that compose the internet. Driven by internet-wide scanning, Censys lets researchers find specific hosts and create aggregate reports on how devices, and certificates are configured and deployed.
This integration was integrated and tested with version 2.0 of Censys.

Some changes have been made that might affect your existing content.
If you are upgrading from a previous of this integration, see [Breaking Changes](#additional-considerations-for-this-version).

## Configure Censys v2 in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The URL of the Censys API server. | True |
| API Token | Personal Access Token from Censys Platform | True |
| Organization ID | The unique identifier for your Censys organization. | True |
| Trust any certificate (not secure) |  | False |
| Use system proxy settings |  | False |
| Determine IP score by labels (for paid subscribers) | Censys API provides reputation data exclusively to paid subscribers. <br/>When set to True, the integration will use labels to determine the IP score.  | False |
| IP Malicious labels | Used only when \`Determine IP score by labels\` is set.<br/>Labels to classify IP as Malicious.<br/>Input can be an array or comma-separated values. | False |
| IP Suspicious labels | Used when \`Determine IP score by labels\` is set.<br/>Labels to classify IP as Suspicious.<br/>Input can be an array or comma-separated values. | False |
| Malicious labels threshold | Determines the minimum number of labels returned that are classified as malicious for IP. | False |
| Suspicious labels threshold | Determines the minimum number of labels returned that are classified as suspicious for IP. | False |
| Source Reliability | Reliability of the source providing the intelligence data. |  |

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
| Censys.View.dns.names | String | DNS Names. |
| Censys.View.ip | String | The host’s IP address. |
| Censys.View.location.continent | String | The continent of the host's detected location \(e.g., North America, Europe, Asia, South America, Africa, Oceania\). |
| Censys.View.location.coordinates | Unknown | The estimated coordinates of the host's detected location. |
| Censys.View.location.country | String | The name of the country of the host's detected location. |
| Censys.View.location.country_code | String | The two-letter ISO 3166-1 alpha-2 country code of the host's detected location \(e.g., US, CN, GB, RU\). |
| Censys.View.location.postal_code | String | The postal code \(if applicable\) of the host's detected location. |
| Censys.View.location.timezone | String | The IANA time zone database name of the host's detected location. |
| Censys.View.services.dns | Unknown | DNS information. |
| Censys.View.services.port | Number | The port the service was reached at. |
| Censys.View.services.protocol | String | The name of the service on the port. This is typically the L7 protocol \(e.g., “HTTP”\); however, in the case that a more specific HTTP-based protocol is found \(e.g., Kubernetes or Prometheus\), the field will show that. This field indicates where protocol-specific data will be located. |
| Censys.View.services.transport_protocol | String | The transport protocol \(known in OSI model as L4\) used to contact this service \(i.e., UDP or TCP\). |
| Censys.View.services.banner | String | The banner as a part of the protocol scan. That field will be nested in the protocol-specific data under the service_name field. |
| Censys.View.services.cert | Unknown | A subset of the parsed details of the certificate, including the issuer, subject, fingerprint, names, public keys, and signature. |
| Censys.View.fingerprint_sha256 | String | The SHA2-256 digest over the DER encoding of the certificate. |
| Censys.View.fingerprint_md5 | String | The MD5 digest over the DER encoding of the certificate. |
| Censys.View.fingerprint_sha1 | String | The SHA1 digest over the DER encoding of the certificate. |
| Censys.View.fingerprint_sha256 | String | The SHA2-256 digest over the DER encoding of the certificate. |
| Censys.View.parsed.issuer.common_name | String | Common name. |
| Censys.View.parsed.issuer.country | String | Country name. |
| Censys.View.parsed.issuer.organization | String | Organization name. |
| Censys.View.parsed.issuer_dn | String | Information about the certificate authority that issued the certificate. |
| Censys.View.parsed.serial_number | String | The issuer-specific identifier of the certificate. |
| Censys.View.parsed.signature.signature_algorithm.name | String | Name of signature algorithm, e.g., SHA1-RSA or ECDSA-SHA512. Unknown algorithms get an integer ID. |
| Censys.View.parsed.signature.signature_algorithm.oid | String | The object identifier of the signature algorithm, in dotted-decimal notation. |
| Censys.View.parsed.subject.common_name | String | Common name. |
| Censys.View.parsed.subject.country | String | Country name. |
| Censys.View.parsed.subject.locality | String | Locality name. |
| Censys.View.parsed.subject.organization | String | The name of the organization to which the certificate was issued, if available. |
| Censys.View.parsed.subject.province | String | State of province name. |
| Censys.View.parsed.subject_dn | String | Information about the entity that was issued the certificate. |
| Censys.View.parsed.subject_key_info.fingerprint_sha256 | String | The SHA2-256 digest calculated over the certificate's DER encoding. |
| Censys.View.parsed.subject_key_info.key_algorithm.name | String | Name of public key type, e.g., RSA or ECDSA. |
| IP.Address | String | IP address. |
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
                "description": "GOOGLE - Google LLC",
                "name": "GOOGLE - Google LLC"
            },
            "dns": {
                "forward_dns": {
                    "2.fangji123.xyz": {
                        "name": "2.fangji123.xyz",
                        "record_type": "a",
                        "resolve_time": "2026-01-28T02:58:34Z"
                    }
                }
            }
        }
    }
}
```

### cen-search

***
Return previews of hosts matching a specified search query or a list of certificates that match the given query.

#### Base Command

`cen-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Query used to search for hosts with matching attributes. Uses the Censys Search Language. | Required |
| page_size | The maximum number of hits to return in each response (minimum of 0, maximum of 100). (Applies for the host search.). Default is 50. | Optional |
| limit | The number of results to return. Default is 50. | Optional |
| index | The index from which to retrieve data. Possible values are: ipv4, certificates. | Required |
| fields | The fields to return. (Applies for the certificates search.). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Censys.Search.autonomous_system.asn | Number | The autonomous system number \(ASN\) that the host is in. |
| Censys.Search.autonomous_system.bgp_prefix | String | The autonomous system's CIDR. |
| Censys.Search.autonomous_system.country_code | String | The autonomous system's two-letter, ISO 3166-1 alpha-2 country code \(e.g., US, CN, GB, RU\). |
| Censys.Search.autonomous_system.description | String | A brief description of the autonomous system. |
| Censys.Search.autonomous_system.name | String | The friendly name of the autonomous system. |
| Censys.Search.ip | String | The host’s IP address. |
| Censys.Search.location.continent | String | The continent of the host's detected location \(e.g., North America, Europe, Asia, South America, Africa, Oceania\). |
| Censys.Search.location.coordinates | Unknown | The estimated coordinates of the host's detected location. |
| Censys.Search.location.country | String | The country of the host's detected location. |
| Censys.Search.location.country_code | String | The two-letter ISO 3166-1 alpha-2 country code of the host's detected location \(e.g., US, CN, GB, RU\). |
| Censys.Search.location.timezone | String | The IANA time zone database name of the host's detected location. |
| Censys.Search.services.port | Number | The port the service was reached at. |
| Censys.Search.services.protocol | String | The name of the service on the port. This is typically the L7 protocol \(e.g., “HTTP”\); however, in case a more specific HTTP-based protocol is found \(e.g., Kubernetes or Prometheus\), the field will show that. This field indicates where protocol-specific data will be located. |
| Censys.Search.services.transport_protocol | String | The transport protocol \(known in OSI model as L4\) used to contact this service \(i.e., UDP or TCP\). |
| Censys.Search.fingerprint_sha256 | String | SHA 256 fingerprint. |
| Censys.Search.parsed.issuer.organization | Unknown | The organization name. |
| Censys.Search.names | Unknown | Common names for the entity. |
| Censys.Search.parsed.subject_dn | String | Distinguished name of the entity that the certificate belongs to. |
| Censys.Search.parsed.validity_period.not_after | Date | Timestamp of when the certificate expires. Time zone is UTC. |
| Censys.Search.parsed.validity_period.not_before | Date | Timestamp of when the certificate is first valid. Time zone is UTC. |
| Censys.Search.parsed.issuer_dn | String | Distinguished name of the entity that has signed and issued the certificate. |

#### Command example

```!cen-search index=certificates query="cert.parsed.issuer.common_name: \"Let's Encrypt\"" limit=1```

#### Context Example

```json
{
    "Censys": {
        "Search": {
            "fingerprint_sha256": "0003da4aee3b252097bfc7f871ab6fbe3e08eb94c34ff5cea91aaa29248d3c8b",
            "parsed": {
                "issuer": {
                    "organization": [
                        "Let's Encrypt"
                    ]
                },
                "issuer_dn": "C=US, ST=Let's Encrypt, O=Let's Encrypt, CN=Let's Encrypt Authority X3",
                "subject_dn": "C=AU, ST=Some-State, O=Internet Widgits Pty Ltd",
                "validity_period": {
                    "not_after": "2026-04-15T00:50:59Z",
                    "not_before": "2025-04-15T00:50:59Z"
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Search results for query "cert.parsed.issuer.common_name: "Let's Encrypt""
>
>|Issuer|Issuer DN|SHA256|Subject DN|Validity not after|Validity not before|
>|---|---|---|---|---|---|
>| Let's Encrypt | C=US, ST=Let's Encrypt, O=Let's Encrypt, CN=Let's Encrypt Authority X3 | 0003da4aee3b252097bfc7f871ab6fbe3e08eb94c34ff5cea91aaa29248d3c8b | C=AU, ST=Some-State, O=Internet Widgits Pty Ltd | 2026-04-15T00:50:59Z | 2025-04-15T00:50:59Z |

#### Command example

```!cen-search index=ipv4 query="host.services.protocol:HTTP" limit=1```

#### Context Example

```json
{
    "Censys": {
        "Search": {
            "autonomous_system": {
                "asn": 4766,
                "bgp_prefix": "10.0.0.0/12",
                "country_code": "KR",
                "description": "KIXS-AS-KR Korea Telecom",
                "name": "KIXS-AS-KR Korea Telecom"
            },
            "dns": {
            }
        }
    }
}
```

### domain

***
Return all related IPs as relationships.

#### Base Command

`domain`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | A comma-separated list of domains to check. | Required |

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
| Censys.Domain.autonomous_system.asn | Number | The Autonomous System Number \(ASN\) associated with the domain. |
| Censys.Domain.autonomous_system.name | String | The name of the autonomous system associated with the domain. |
| Censys.Domain.autonomous_system.bgp_prefix | String | The BGP prefix of the autonomous system associated with the domain. |
| Censys.Domain.autonomous_system.description | String | The description of the autonomous system associated with the domain. |
| Censys.Domain.services.transport_protocol | String | The transport protocol used by the service associated with the domain. |
| Censys.Domain.services.port | Number | The port number associated with the service associated with the domain. |
| Censys.Domain.services.protocol | String | The name of the service associated with the domain. |
| Censys.Domain.services.cert | String | The SSL/TLS certificate associated with the service associated with the domain. |
| Censys.Domain.ip | String | The IP address associated with the domain. |
| Censys.Domain.dns.reverse_dns.names | String | The reverse DNS names associated with the domain. |
| Domain.Name | string | The domain. |
| Domain.Relationships.EntityA | string | The domain name. |
| Domain.Relationships.EntityAType | string | The entity type. |
| Domain.Relationships.EntityB | string | The entity B. |
| Domain.Relationships.EntityBType | string | The entity B type. |
| Domain.Relationships.Relationship | string | The relationship type. |
| DBotScore.Indicator | unknown | The indicator that was tested. |
| DBotScore.Type | unknown | The indicator type. |
| DBotScore.Score | unknown | The actual score. |
| DBotScore.Vendor | unknown | The vendor used to calculate the score. |

#### Command example

```!domain domain=amazon.com,google.com```

#### Context Example

```json
{
    "Censys": {
        "Domain": [
            {
                "autonomous_system": {
                    "asn": 14618,
                    "bgp_prefix": "10.0.0.0/13",
                    "country_code": "US",
                    "description": "AMAZON-AES - Amazon.com, Inc.",
                    "name": "AMAZON-AES - Amazon.com, Inc."
                },
                "dns": {
                    "forward_dns": {
                        "amazon.com": {
                            "name": "amazon.com",
                            "record_type": "a",
                            "resolve_time": "2026-01-27T20:29:15Z"
                        }
                    },
                    "names": [
                        "amazon.com"
                    ],
                    "reverse_dns": {
                        "names": [
                            "ec2-192-0-2-1.compute-1.amazonaws.com"
                        ],
                        "resolve_time": "2026-01-13T16:21:30Z"
                    }
                },
                "ip": "192.0.2.1",
                "location": {
                    "city": "Ashburn",
                    "continent": "North America",
                    "coordinates": {
                        "latitude": 39.04372,
                        "longitude": -77.48749
                    },
                    "country": "United States",
                    "country_code": "US",
                    "postal_code": "20147",
                    "province": "Virginia",
                    "timezone": "America/New_York"
                },
                "service_count": 2,
                "services": [
                    {
                        "port": 80,
                        "protocol": "HTTP",
                        "transport_protocol": "tcp"
                    },
                    {
                        "banner": "HTTP/1.1 400 Bad Request\r\nServer: Server\r\nDate:  <REDACTED>\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n",
                        "banner_hash_sha256": "0269a8a467d7591227ba20e7be6f0992ff31791f5235e31a60fc5ff168a4c921",
                        "cert": {
                            "added_at": "2025-11-06T17:17:35Z",
                            "ct": {
                                "entries": {
                                    "cloudflare_nimbus_2026": {
                                        "added_to_ct_at": "2025-11-06T17:48:17Z",
                                        "ct_to_censys_at": "2025-11-06T18:54:38Z",
                                        "index": 846730169
                                    },
                                    "google_argon_2026_h2": {
                                        "added_to_ct_at": "2025-11-06T17:41:18Z",
                                        "ct_to_censys_at": "2025-11-06T17:45:17Z",
                                        "index": 189639680
                                    },
                                    "google_xenon_2026_h2": {
                                        "added_to_ct_at": "2025-11-06T17:41:18Z",
                                        "ct_to_censys_at": "2025-11-06T17:51:37Z",
                                        "index": 143726358
                                    },
                                    "letsencrypt_ct_oak_2026_h2": {
                                        "added_to_ct_at": "2025-11-06T17:41:18Z",
                                        "ct_to_censys_at": "2025-11-06T17:49:49Z",
                                        "index": 117540704
                                    },
                                    "letsencrypt_ct_sycamore_2026_h2": {
                                        "added_to_ct_at": "2025-11-06T17:45:49Z",
                                        "ct_to_censys_at": "2025-12-12T18:19:25Z",
                                        "index": 22212155
                                    },
                                    "letsencrypt_ct_willow_2026_h2": {
                                        "added_to_ct_at": "2025-11-06T17:46:09Z",
                                        "ct_to_censys_at": "2025-12-12T19:58:13Z",
                                        "index": 22208638
                                    },
                                    "trustasia_log_2026_a": {
                                        "added_to_ct_at": "2025-11-17T04:30:41Z",
                                        "ct_to_censys_at": "2025-11-17T18:18:36Z",
                                        "index": 88656657
                                    },
                                    "trustasia_log_2026_b": {
                                        "added_to_ct_at": "2025-11-10T06:27:14Z",
                                        "ct_to_censys_at": "2025-11-10T06:32:24Z",
                                        "index": 86980442
                                    }
                                }
                            },
                            "ever_seen_in_scan": true,
                            "fingerprint_md5": "3a20cd834e379eb01e8fca18625a095b",
                            "fingerprint_sha1": "3152b1059fa057395743ea0ca8068c6dccd133c5",
                            "fingerprint_sha256": "8c062771b98a854ef04f86bc5e3a97366a927c6c3fcc2647c67b988aceea3092",
                            "modified_at": "2025-12-12T19:58:13Z",
                            "names": [
                                "*.aa.peg.a2z.com",
                                "*.ab.peg.a2z.com",
                                "*.ac.peg.a2z.com",
                                "*.bz.peg.a2z.com",
                                "*.peg.a2z.com",
                                "amazon.co.jp",
                                "amazon.co.uk",
                                "amazon.com",
                                "amazon.com.au",
                                "amazon.de",
                                "amazon.jp",
                                "amzn.com",
                                "buckeye-retail-website.amazon.com",
                                "buybox.amazon.com",
                                "corporate.amazon.com",
                                "edgeflow-dp.aero.04f01a85e-frontier.amazon.com.au",
                                "edgeflow-dp.aero.47cf2c8c9-frontier.amazon.com",
                                "edgeflow-dp.aero.4d5ad1d2b-frontier.amazon.co.jp",
                                "edgeflow-dp.aero.abe2c2f23-frontier.amazon.de",
                                "edgeflow-dp.aero.bfbdc3ca1-frontier.amazon.co.uk",
                                "edgeflow.aero.04f01a85e-frontier.amazon.com.au",
                                "edgeflow.aero.47cf2c8c9-frontier.amazon.com",
                                "edgeflow.aero.4d5ad1d2b-frontier.amazon.co.jp",
                                "edgeflow.aero.abe2c2f23-frontier.amazon.de",
                                "edgeflow.aero.bfbdc3ca1-frontier.amazon.co.uk",
                                "home.amazon.com",
                                "huddles.amazon.com",
                                "iphone.amazon.com",
                                "origin-www.amazon.co.jp",
                                "origin-www.amazon.co.uk",
                                "origin-www.amazon.com",
                                "origin-www.amazon.com.au",
                                "origin-www.amazon.de",
                                "origin2-www.amazon.co.jp",
                                "origin2-www.amazon.com",
                                "uedata.amazon.co.uk",
                                "uedata.amazon.com",
                                "us.amazon.com",
                                "www.amazon.co.jp",
                                "www.amazon.co.uk",
                                "www.amazon.com",
                                "www.amazon.com.au",
                                "www.amazon.de",
                                "www.amazon.jp",
                                "www.amzn.com",
                                "yp.amazon.com"
                            ],
                            "parent_spki_fingerprint_sha256": "a0f06408dfb8d5e0095d4a968536efd3ecdc75025691b142170e7eb66c85b39a",
                            "parent_spki_subject_fingerprint_sha256": "a0f06408dfb8d5e0095d4a968536efd3ecdc75025691b142170e7eb66c85b39a",
                            "parse_status": "success",
                            "parsed": {
                                "extensions": {
                                    "authority_info_access": {
                                        "issuer_urls": [
                                            "http://example.com/cacerts/DigiCertGlobalCAG2.crt"
                                        ],
                                        "ocsp_urls": [
                                            "http://example.com/ocsp"
                                        ]
                                    },
                                    "authority_key_id": "246e2b2dd06a925151256901aa9a47a689e74020",
                                    "basic_constraints": {},
                                    "certificate_policies": [
                                        {
                                            "cps": [
                                                "http://example.com/CPS"
                                            ],
                                            "id": "1.2.3.4.5.6.7"
                                        }
                                    ],
                                    "crl_distribution_points": [
                                        "http://example.com/crl/DigiCertGlobalCAG2.crl",
                                        "http://example.com/crl2/DigiCertGlobalCAG2.crl"
                                    ],
                                    "extended_key_usage": {
                                        "client_auth": true,
                                        "server_auth": true
                                    },
                                    "key_usage": {
                                        "digital_signature": true,
                                        "key_encipherment": true,
                                        "value": 5
                                    },
                                    "signed_certificate_timestamps": [
                                        {
                                            "log_id": "d809553b944f7affc816196f944f85abb0f8fc5e8755260f15d12e72bb454b14",
                                            "signature": {
                                                "hash_algorithm": "SHA256",
                                                "signature": "304402203a1a41e357a63d9b599cadecafc2215d60f6b884187b02df237bb196c262d4dd02201431d3cca905bc2ba7bdbc5891269976330bd6696fcc6e4509ace0c82a5b80d8",
                                                "signature_algorithm": "ECDSA"
                                            },
                                            "timestamp": "2025-11-06T16:37:35Z"
                                        },
                                        {
                                            "log_id": "c2317e574519a345ee7f38deb29041ebc7c2215a22bf7fd5b5ad769ad90e52cd",
                                            "signature": {
                                                "hash_algorithm": "SHA256",
                                                "signature": "3045022100fd699c45d2e93df414102920a416677928078dd171201f18250ada49aecf84f202204f3f00142c85bb1e2973c106b856c7b9ec2af1958acfbdcc8c6aedf3e5d00d64",
                                                "signature_algorithm": "ECDSA"
                                            },
                                            "timestamp": "2025-11-06T16:37:35Z"
                                        },
                                        {
                                            "log_id": "944e4387faecc1ef81f3192426a8186501c7d35f3802013f72677d55372e19d8",
                                            "signature": {
                                                "hash_algorithm": "SHA256",
                                                "signature": "30440220432960ef2fde72dab8edc759403700640c61392d80df91c3688876a43b9d24f2022013695dd7abbe84eac82469bb7a6c37afd8a8999eac07d1ed330e41e1495b186d",
                                                "signature_algorithm": "ECDSA"
                                            },
                                            "timestamp": "2025-11-06T16:37:35Z"
                                        }
                                    ],
                                    "subject_alt_name": {
                                        "dns_names": [
                                            "amazon.co.uk",
                                            "uedata.amazon.co.uk",
                                            "www.amazon.co.uk",
                                            "origin-www.amazon.co.uk",
                                            "*.peg.a2z.com",
                                            "amazon.com",
                                            "amzn.com",
                                            "uedata.amazon.com",
                                            "us.amazon.com",
                                            "www.amazon.com",
                                            "www.amzn.com",
                                            "corporate.amazon.com",
                                            "buybox.amazon.com",
                                            "iphone.amazon.com",
                                            "yp.amazon.com",
                                            "home.amazon.com",
                                            "origin-www.amazon.com",
                                            "origin2-www.amazon.com",
                                            "buckeye-retail-website.amazon.com",
                                            "huddles.amazon.com",
                                            "amazon.de",
                                            "www.amazon.de",
                                            "origin-www.amazon.de",
                                            "amazon.co.jp",
                                            "amazon.jp",
                                            "www.amazon.jp",
                                            "www.amazon.co.jp",
                                            "origin-www.amazon.co.jp",
                                            "*.aa.peg.a2z.com",
                                            "*.ab.peg.a2z.com",
                                            "*.ac.peg.a2z.com",
                                            "origin-www.amazon.com.au",
                                            "www.amazon.com.au",
                                            "*.bz.peg.a2z.com",
                                            "amazon.com.au",
                                            "origin2-www.amazon.co.jp",
                                            "edgeflow.aero.4d5ad1d2b-frontier.amazon.co.jp",
                                            "edgeflow.aero.04f01a85e-frontier.amazon.com.au",
                                            "edgeflow.aero.47cf2c8c9-frontier.amazon.com",
                                            "edgeflow.aero.abe2c2f23-frontier.amazon.de",
                                            "edgeflow.aero.bfbdc3ca1-frontier.amazon.co.uk",
                                            "edgeflow-dp.aero.4d5ad1d2b-frontier.amazon.co.jp",
                                            "edgeflow-dp.aero.04f01a85e-frontier.amazon.com.au",
                                            "edgeflow-dp.aero.47cf2c8c9-frontier.amazon.com",
                                            "edgeflow-dp.aero.bfbdc3ca1-frontier.amazon.co.uk",
                                            "edgeflow-dp.aero.abe2c2f23-frontier.amazon.de"
                                        ]
                                    },
                                    "subject_key_id": "aaf8a5eaec987c7117d41fbd39c95f7b71020a1e"
                                },
                                "issuer": {
                                    "common_name": [
                                        "DigiCert Global CA G2"
                                    ],
                                    "country": [
                                        "US"
                                    ],
                                    "organization": [
                                        "DigiCert Inc"
                                    ]
                                },
                                "issuer_dn": "C=US, O=DigiCert Inc, CN=DigiCert Global CA G2",
                                "ja4x": "a373a9f83c6b_7022c563de38_2cdf432ec278",
                                "serial_number": "1377932119697704108067612670015473867",
                                "serial_number_hex": "0109614c77ec09ea900f923281c688cb",
                                "signature": {
                                    "signature_algorithm": {
                                        "name": "SHA256-RSA",
                                        "oid": "1.2.840.113549.1.1.11"
                                    },
                                    "valid": true,
                                    "value": "8fcff8d419d57562f4f719a070ea5a2c02083c40f966aab18848094b6cc9b76156f887193adfe5a09f3f384f060dfd0b31acfdd0c0cb7e86d51e681940044fb2f116f59b58c2d962b7796e9727c029f695b5790c2ed398b3f8129088a30327951477e11df26c7eb3675edf61051e9f64b97d85d58ee3d5b411cf17be2fd9431edfa0a32c4a1f5672465a0bb5c0f60f995c68a743bc4db9fb58e3c975a50055a92edc81ae9da05609de2dc49870f4ccb1f52f772aff214190a8ac9c3dda583ce7e0b5deb5157d583a2a0dfb4e8f80f07cd6cf8e3ddd18aff99660740f32cb45c4d2ec1ef30db280ae0de0ef77e12f5637bf4bef8e1cc245a3f29855a81bd466f5"
                                },
                                "subject": {
                                    "common_name": [
                                        "*.peg.a2z.com"
                                    ]
                                },
                                "subject_dn": "CN=*.peg.a2z.com",
                                "subject_key_info": {
                                    "fingerprint_sha256": "325f1c87dc001e02a27de95ec7774bfb6d4b2ccf9ef5d5161696ff9936410fba",
                                    "key_algorithm": {
                                        "name": "RSA",
                                        "oid": "1.2.840.113549.1.1.1"
                                    },
                                    "rsa": {
                                        "exponent": 65537,
                                        "length": 2048,
                                        "modulus": "b865ad75cfa6bc86c43f193a00b6c712d249f7a0c2d8410dbd65a7480333439802acae4eed23ef679fd90931caa55b8949faf283d76b8767e983cde784d3c5ec860361165458fbbb24989b1abff67129eeba7d33f808a68b518641a05839ec5f87846863e3ba9379c230d23091a8d6c758b486d19a2d11ae97c5c06e951d5d3ecf927fc162b42fd00cfc623f2fa886cd8f14448fc155cd12e48bbe571fbafb532299fc9e816683953d254865fafe657097195a205dd53bcf400dc65c7b2960e46a02ec48534e517c1cb3f211cc75ca70166bba67d4587420cc0c2083aba4f0858dcbb2bc74f2f7ac14e9dd4d24516bd53037559263fd5a50656f39940aba6ce3"
                                    }
                                },
                                "validity_period": {
                                    "length_seconds": 27648000,
                                    "not_after": "2026-09-21T23:59:59Z",
                                    "not_before": "2025-11-06T00:00:00Z"
                                },
                                "version": 3
                            },
                            "revocation": {
                                "crl": {
                                    "reason": "unspecified"
                                },
                                "ocsp": {
                                    "reason": "unspecified"
                                }
                            },
                            "spki_fingerprint_sha256": "395a16ab1bc812de8784405859a631ac6519e85543fd9e7dbc8c52b33f865dc8",
                            "spki_subject_fingerprint_sha256": "395a16ab1bc812de8784405859a631ac6519e85543fd9e7dbc8c52b33f865dc8",
                            "tbs_fingerprint_sha256": "9cd2c97a60d07862c482661096c0239fcc60a689fd86db77133908a4dc562c4d",
                            "tbs_no_ct_fingerprint_sha256": "34752e5613070cd06115be2c4a2b8df47a53faef804055febc682db29a889f64",
                            "validated_at": "2026-01-27T19:29:18Z",
                            "validation": {
                                "apple": {
                                    "chains": [
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f"
                                            ]
                                        },
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "6523c34f1e879add7603cb2048a898a5e2f0c6c4b512c0d22782b85d43ae3371",
                                                "4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161"
                                            ]
                                        },
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "79d57b15dfa65c2870eafe11b637765909cfe937b49c15ce7f194030cab395ad",
                                                "4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161"
                                            ]
                                        },
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "a0d609a7e3c434e878a9a1c1bd065b8dcf33aa7efee1b11bc75cce5e5a042080",
                                                "7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf"
                                            ]
                                        },
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "caf8ad697f7bda712ab127a8ad8b83f74a91a0de1784a1b483fef9ac79b67513",
                                                "7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf"
                                            ]
                                        }
                                    ],
                                    "ever_valid": true,
                                    "had_trusted_path": true,
                                    "has_trusted_path": true,
                                    "is_valid": true,
                                    "parents": [
                                        "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b"
                                    ],
                                    "type": "leaf"
                                },
                                "chrome": {
                                    "chains": [
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f"
                                            ]
                                        },
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "6523c34f1e879add7603cb2048a898a5e2f0c6c4b512c0d22782b85d43ae3371",
                                                "4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161"
                                            ]
                                        },
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "79d57b15dfa65c2870eafe11b637765909cfe937b49c15ce7f194030cab395ad",
                                                "4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161"
                                            ]
                                        },
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "a0d609a7e3c434e878a9a1c1bd065b8dcf33aa7efee1b11bc75cce5e5a042080",
                                                "7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf"
                                            ]
                                        },
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "caf8ad697f7bda712ab127a8ad8b83f74a91a0de1784a1b483fef9ac79b67513",
                                                "7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf"
                                            ]
                                        }
                                    ],
                                    "ever_valid": true,
                                    "had_trusted_path": true,
                                    "has_trusted_path": true,
                                    "is_valid": true,
                                    "parents": [
                                        "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b"
                                    ],
                                    "type": "leaf"
                                },
                                "microsoft": {
                                    "chains": [
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f"
                                            ]
                                        },
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "0ba8c0d459b76abc0825294f565e24f4f169d4a4819d0692d371522d297724b8",
                                                "2399561127a57125de8cefea610ddf2fa078b5c8067f4e828290bfb860e84b3c"
                                            ]
                                        },
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "6523c34f1e879add7603cb2048a898a5e2f0c6c4b512c0d22782b85d43ae3371",
                                                "4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161"
                                            ]
                                        },
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "79d57b15dfa65c2870eafe11b637765909cfe937b49c15ce7f194030cab395ad",
                                                "4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161"
                                            ]
                                        },
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "a0d609a7e3c434e878a9a1c1bd065b8dcf33aa7efee1b11bc75cce5e5a042080",
                                                "7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf"
                                            ]
                                        }
                                    ],
                                    "ever_valid": true,
                                    "had_trusted_path": true,
                                    "has_trusted_path": true,
                                    "is_valid": true,
                                    "parents": [
                                        "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b"
                                    ],
                                    "type": "leaf"
                                },
                                "nss": {
                                    "chains": [
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f"
                                            ]
                                        },
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "6523c34f1e879add7603cb2048a898a5e2f0c6c4b512c0d22782b85d43ae3371",
                                                "4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161"
                                            ]
                                        },
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "79d57b15dfa65c2870eafe11b637765909cfe937b49c15ce7f194030cab395ad",
                                                "4348a0e9444c78cb265e058d5e8944b4d84f9662bd26db257f8934a443c70161"
                                            ]
                                        },
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "a0d609a7e3c434e878a9a1c1bd065b8dcf33aa7efee1b11bc75cce5e5a042080",
                                                "7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf"
                                            ]
                                        },
                                        {
                                            "sha256fp": [
                                                "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                                "caf8ad697f7bda712ab127a8ad8b83f74a91a0de1784a1b483fef9ac79b67513",
                                                "7431e5f4c3c1ce4690774f0b61e05440883ba9a01ed00ba6abd7806ed3b118cf"
                                            ]
                                        }
                                    ],
                                    "ever_valid": true,
                                    "had_trusted_path": true,
                                    "has_trusted_path": true,
                                    "is_valid": true,
                                    "parents": [
                                        "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b"
                                    ],
                                    "type": "leaf"
                                }
                            },
                            "validation_level": "dv",
                            "zlint": {
                                "failed_lints": [
                                    "n_subject_common_name_included"
                                ],
                                "notices_present": true,
                                "timestamp": "2025-11-06T17:17:34Z",
                                "version": 3
                            }
                        },
                        "endpoints": [
                            {
                                "banner": "HTTP/1.1 400 Bad Request\r\nServer: Server\r\nDate:  <REDACTED>\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n",
                                "banner_hash_sha256": "0269a8a467d7591227ba20e7be6f0992ff31791f5235e31a60fc5ff168a4c921",
                                "endpoint_type": "HTTP",
                                "hostname": "192.0.2.1",
                                "http": {
                                    "body": "<!DOCTYPE html><html><head><title>x</title></head><body></body></html>\n",
                                    "body_hash_sha1": "e441bba8b691ad0fff0bccb75974880018ab41d6",
                                    "body_hash_sha256": "73f8ae8c11daa6ad905107970e55c3c64cd7133561e9e91e650aab092ba7245e",
                                    "body_size": 71,
                                    "headers": {
                                        "Connection": {
                                            "headers": [
                                                "close"
                                            ]
                                        },
                                        "Content-Type": {
                                            "headers": [
                                                "text/html"
                                            ]
                                        },
                                        "Date": {
                                            "headers": [
                                                "<REDACTED>"
                                            ]
                                        },
                                        "Server": {
                                            "headers": [
                                                "Server"
                                            ]
                                        },
                                        "Transfer-Encoding": {
                                            "headers": [
                                                "chunked"
                                            ]
                                        }
                                    },
                                    "html_tags": [
                                        "<title>x</title>"
                                    ],
                                    "html_title": "x",
                                    "protocol": "HTTP/1.1",
                                    "status_code": 400,
                                    "status_reason": "Bad Request",
                                    "supported_versions": [
                                        "HTTP/1.1"
                                    ],
                                    "uri": "https://192.0.2.1/"
                                },
                                "ip": "192.0.2.1",
                                "path": "/",
                                "port": 443,
                                "scan_time": "2026-01-27T21:48:42Z",
                                "transport_protocol": "tcp"
                            }
                        ],
                        "ip": "8.8.8.8",
                        "ja4tscan": {
                            "fingerprint": "62643_2-4-8-1-3_1460_7_1-2-4-9-17",
                            "scan_time": "2026-01-27T04:00:58Z"
                        },
                        "port": 443,
                        "protocol": "HTTP",
                        "scan_time": "2026-01-27T21:48:42Z",
                        "tls": {
                            "cipher_selected": "TLS_AES_128_GCM_SHA256",
                            "fingerprint_sha256": "8c062771b98a854ef04f86bc5e3a97366a927c6c3fcc2647c67b988aceea3092",
                            "ja3s": "f4febc55ea12b31ae17cfb7e614afda8",
                            "ja4s": "t130200_1301_a56c5b993250",
                            "presented_chain": [
                                {
                                    "fingerprint_sha256": "8fac576439c9fd3ef153b51f9edd0d381b5df7b87559cebeca04297dd44a639b",
                                    "issuer_dn": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2",
                                    "subject_dn": "C=US, O=DigiCert Inc, CN=DigiCert Global CA G2"
                                },
                                {
                                    "fingerprint_sha256": "aadadd5a879d2eb8c41a89597291292709d42052f5b6399541c694c3b7353cd1",
                                    "issuer_dn": "C=US, O=VeriSign\\, Inc., OU=VeriSign Trust Network, OU=(c) 2006 VeriSign\\, Inc. - For authorized use only, CN=VeriSign Class 3 Public Primary Certification Authority - G5",
                                    "subject_dn": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=DigiCert Global Root G2"
                                }
                            ],
                            "version_selected": "tlsv1_3",
                            "versions": [
                                {
                                    "ja3s": "f4febc55ea12b31ae17cfb7e614afda8",
                                    "ja4s": "t130200_1301_a56c5b993250",
                                    "version": "tlsv1_3"
                                },
                                {
                                    "ja3s": "2b1f517a72b7346c86d59ef328167d49",
                                    "ja4s": "t120300_c02f_cbb8871a0652",
                                    "version": "tlsv1_2"
                                },
                                {
                                    "ja3s": "24abcc4acb0869d8e569d403dfe55a99",
                                    "ja4s": "t110300_c013_cbb8871a0652",
                                    "version": "tlsv1_1"
                                },
                                {
                                    "ja3s": "7ac2b84fdf4dcd940d5099b55a649c04",
                                    "ja4s": "t100300_c013_cbb8871a0652",
                                    "version": "tlsv1_0"
                                }
                            ]
                        },
                        "transport_protocol": "tcp"
                    }
                ],
                "whois": {
                    "network": {
                        "allocation_type": "REALLOCATION",
                        "cidrs": [
                            "10.0.0.0/13"
                        ],
                        "created": "2024-02-21T00:00:00Z",
                        "handle": "AMAZON-IAD",
                        "name": "Amazon Data Services Northern Virginia",
                        "updated": "2024-02-21T00:00:00Z"
                    },
                    "organization": {
                        "abuse_contacts": [
                            {
                                "email": "abuse@example.com",
                                "handle": "AEA8-ARIN",
                                "name": "Amazon EC2 Abuse"
                            }
                        ],
                        "admin_contacts": [
                            {
                                "email": "admin@example.com",
                                "handle": "IPMAN40-ARIN",
                                "name": "IP Management"
                            }
                        ],
                        "city": "Herndon",
                        "country": "US",
                        "handle": "ADSN-1",
                        "name": "Amazon Data Services Northern Virginia",
                        "postal_code": "20171",
                        "state": "VA",
                        "street": "13200 Woodland Park Road",
                        "tech_contacts": [
                            {
                                "email": "noc@example.com",
                                "handle": "ANO24-ARIN",
                                "name": "Amazon EC2 Network Operations"
                            }
                        ]
                    }
                }
            }        
        ]
    },
    "DBotScore": [
        {
            "Indicator": "amazon.com",
            "Reliability": "C - Fairly reliable",
            "Score": 0,
            "Type": "domain",
            "Vendor": "CensysV2"
        },
        {
            "Indicator": "google.com",
            "Reliability": "C - Fairly reliable",
            "Score": 3,
            "Type": "domain",
            "Vendor": "CensysV2"
        }
    ],
    "Domain": [
        {
            "Name": "amazon.com",
            "Relationships": [
                {
                    "EntityA": "amazon.com",
                    "EntityAType": "Domain",
                    "EntityB": "192.0.2.1",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                },
                {
                    "EntityA": "amazon.com",
                    "EntityAType": "Domain",
                    "EntityB": "192.0.2.2",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                },
                {
                    "EntityA": "amazon.com",
                    "EntityAType": "Domain",
                    "EntityB": "192.0.2.3",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                }
            ]
        },
        {
            "Malicious": {
                "Description": "Matched malicious labels: IPV6",
                "Vendor": "CensysV2"
            },
            "Name": "google.com",
            "Relationships": [
                {
                    "EntityA": "google.com",
                    "EntityAType": "Domain",
                    "EntityB": "2001:db8::1",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                },
                {
                    "EntityA": "google.com",
                    "EntityAType": "Domain",
                    "EntityB": "2001:db8::2",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                },
                {
                    "EntityA": "google.com",
                    "EntityAType": "Domain",
                    "EntityB": "2001:db8::3",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                },
                {
                    "EntityA": "google.com",
                    "EntityAType": "Domain",
                    "EntityB": "2001:db8::4",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                },
                {
                    "EntityA": "google.com",
                    "EntityAType": "Domain",
                    "EntityB": "2001:db8::5",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                },
                {
                    "EntityA": "google.com",
                    "EntityAType": "Domain",
                    "EntityB": "2001:db8::6",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                },
                {
                    "EntityA": "google.com",
                    "EntityAType": "Domain",
                    "EntityB": "2001:db8::7",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                },
                {
                    "EntityA": "google.com",
                    "EntityAType": "Domain",
                    "EntityB": "2001:db8::8",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                },
                {
                    "EntityA": "google.com",
                    "EntityAType": "Domain",
                    "EntityB": "2001:db8::9",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                },
                {
                    "EntityA": "google.com",
                    "EntityAType": "Domain",
                    "EntityB": "2001:db8::10",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                },
                {
                    "EntityA": "google.com",
                    "EntityAType": "Domain",
                    "EntityB": "192.0.2.10",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                },
                {
                    "EntityA": "google.com",
                    "EntityAType": "Domain",
                    "EntityB": "192.0.2.11",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                },
                {
                    "EntityA": "google.com",
                    "EntityAType": "Domain",
                    "EntityB": "192.0.2.12",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                },
                {
                    "EntityA": "google.com",
                    "EntityAType": "Domain",
                    "EntityB": "192.0.2.13",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                },
                {
                    "EntityA": "google.com",
                    "EntityAType": "Domain",
                    "EntityB": "192.0.2.14",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                },
                {
                    "EntityA": "google.com",
                    "EntityAType": "Domain",
                    "EntityB": "192.0.2.15",
                    "EntityBType": "IP",
                    "Relationship": "related-to"
                }
            ]
        }
    ]
}
```

#### Human Readable Output

>### Information for IP 8.8.8.8
>
>|ASN|Network|Protocols|Routing|Whois Last Updated|
>|---|---|---|---|---|
>| 15169 | GOOGLE - Google LLC | 53/DNS, 443/UNKNOWN, 443/HTTP, 853/UNKNOWN | 8.8.8.0/24 | 2023-12-28T00:00:00Z |

#### Command example

```!cen-view index=certificates query=9d3b51a6b80daf76e074730f19dc01e643ca0c3127d8f48be64cf3302f6622cc limit=1```

#### Context Example

```json
{
    "Censys": {
        "View": {
            "added_at": "1970-01-01T00:00:00Z",
            "ct": {
                "entries": {
                    "digicert_ct1": {
                        "added_to_ct_at": "2015-09-29T19:55:46Z",
                        "ct_to_censys_at": "2018-07-30T04:49:40Z",
                        "index": 165790
                    },
                    "google_aviator": {
                        "index": 8713649
                    },
                    "google_pilot": {
                        "added_to_ct_at": "2015-09-29T19:55:45Z",
                        "ct_to_censys_at": "2018-07-30T15:23:48Z",
                        "index": 9498499
                    },
                    "google_rocketeer": {
                        "added_to_ct_at": "2015-09-29T19:55:45Z",
                        "ct_to_censys_at": "2018-07-30T15:17:12Z",
                        "index": 6663198
                    },
                    "nordu_ct_plausible": {
                        "added_to_ct_at": "2015-10-19T23:17:33Z",
                        "ct_to_censys_at": "2018-07-30T19:53:59Z",
                        "index": 5744025
                    },
                    "symantec_ws_ct": {
                        "added_to_ct_at": "2015-09-29T19:55:46Z",
                        "ct_to_censys_at": "2018-07-30T04:22:53Z",
                        "index": 6913
                    }
                }
            },
            "ever_seen_in_scan": true,
            "fingerprint_md5": "0f263d5e56288c37ade29f7b9977f38d",
            "fingerprint_sha1": "8740f09afc54752b26b295cdc6393c6b8ffd9e6a",
            "fingerprint_sha256": "9d3b51a6b80daf76e074730f19dc01e643ca0c3127d8f48be64cf3302f6622cc",
            "modified_at": "2024-01-23T12:12:35Z",
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
            "parent_spki_subject_fingerprint_sha256": "ec0c72ce7689150e4f62d04f51f0f19713f77cf27ff43cab4035e9e54e846aa9",
            "parse_status": "success",
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
                    "basic_constraints": {},
                    "certificate_policies": [
                        {
                            "id": "1.2.3.4.5.6.7.8.9"
                        },
                        {
                            "id": "1.2.3.4.5.6.7.8.10"
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
                "serial_number": "5878999135690490607",
                "serial_number_hex": "51966690cda902ef",
                "signature": {
                    "signature_algorithm": {
                        "name": "SHA256-RSA",
                        "oid": "1.2.840.113549.1.1.11"
                    },
                    "valid": true,
                    "value": "1e36357c79acc1c99ddec329d06a1695b2e82cc6ee884d6a699e035219fc804df3d090e7e910d88d9f2a3aa300dff16a732c33775bca074b279b6251924f597c160d3b5688b17a525da0818ed16654f7996ab2c81627ad59ee9b4be94b6c2e05873539fdb83b280cbbccf647ba1d44fb2b3beafe0efc9ba2e6258ef809a4cb0bbec54e09dd21236ca10962e6d7b1ae42328bcdc25fa57b650f8aeff1aaef90721098563e8a406567462674b39318f3a6ca54fc651d15ca8eecadff61484a9e3cb078100e6ab96d9d620798752dcf83bdd3b2be69bbdfc22c0e87aff10ce2305d855c6c9a1133e6fc207601f139f0c8fdb3dae5d21371eff9be66de79edcaef6a"
                },
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
                    "ecdsa": {
                        "b": "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                        "curve": "P-256",
                        "gx": "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                        "gy": "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                        "length": 256,
                        "n": "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                        "p": "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                        "pub": "04f680d0e5c3a1162f2420176176add7ba927c0cecb52453bfa84a16c9fe56219b1ec2b31bcf2ae30d5fb45c475edc79725bf57889a3b2a76ec940d567e66fce77",
                        "x": "f680d0e5c3a1162f2420176176add7ba927c0cecb52453bfa84a16c9fe56219b",
                        "y": "1ec2b31bcf2ae30d5fb45c475edc79725bf57889a3b2a76ec940d567e66fce77"
                    },
                    "fingerprint_sha256": "3d4a4bd778be7965e90a13ac361e1ed7836d24c15cd5c093f9cc7e7857f53ea0",
                    "key_algorithm": {
                        "name": "ECDSA",
                        "oid": "1.2.840.10045.2.1"
                    }
                },
                "validity_period": {
                    "length_seconds": 7708841,
                    "not_after": "2015-12-28T00:00:00Z",
                    "not_before": "2015-09-29T18:39:20Z"
                },
                "version": 3
            },
            "spki_subject_fingerprint_sha256": "5eb06b1c29ced84998d3d35a80fa17d3d39e4de96d25539485aecd6360f618dc",
            "tbs_fingerprint_sha256": "1661b59eb7d8cda44f800fabc9ef69ba01506309eedf027f2270105afd1663e4",
            "tbs_no_ct_fingerprint_sha256": "1661b59eb7d8cda44f800fabc9ef69ba01506309eedf027f2270105afd1663e4",
            "validated_at": "2023-09-09T05:55:46Z",
            "validation": {
                "apple": {
                    "chains": [
                        {
                            "sha256fp": [
                                "44336eb05c6c783dc177217a9f6fef75f4524e98045b390803ae9de69eb42b08",
                                "ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a"
                            ]
                        },
                        {
                            "sha256fp": [
                                "9f630426df1d8abfd80ace98871ba833ab9742cb34838de2b5285ed54c0c7dcc",
                                "ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a"
                            ]
                        },
                        {
                            "sha256fp": [
                                "a4124fdaf9cac7baee1cab32e3225d746500c09f3cf3ebb253ef3fbb088afd34",
                                "ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a"
                            ]
                        },
                        {
                            "sha256fp": [
                                "c3f697a92a293d86f9a3ee7ccb970e20e0050b8728cc83ed1b996ce9005d4c36",
                                "ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a"
                            ]
                        }
                    ],
                    "ever_valid": true,
                    "had_trusted_path": true,
                    "parents": [
                        "44336eb05c6c783dc177217a9f6fef75f4524e98045b390803ae9de69eb42b08",
                        "9f630426df1d8abfd80ace98871ba833ab9742cb34838de2b5285ed54c0c7dcc",
                        "a4124fdaf9cac7baee1cab32e3225d746500c09f3cf3ebb253ef3fbb088afd34",
                        "c3f697a92a293d86f9a3ee7ccb970e20e0050b8728cc83ed1b996ce9005d4c36"
                    ],
                    "type": "leaf"
                },
                "chrome": {},
                "microsoft": {
                    "chains": [
                        {
                            "sha256fp": [
                                "44336eb05c6c783dc177217a9f6fef75f4524e98045b390803ae9de69eb42b08",
                                "ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a"
                            ]
                        },
                        {
                            "sha256fp": [
                                "9f630426df1d8abfd80ace98871ba833ab9742cb34838de2b5285ed54c0c7dcc",
                                "ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a"
                            ]
                        },
                        {
                            "sha256fp": [
                                "a4124fdaf9cac7baee1cab32e3225d746500c09f3cf3ebb253ef3fbb088afd34",
                                "ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a"
                            ]
                        },
                        {
                            "sha256fp": [
                                "c3f697a92a293d86f9a3ee7ccb970e20e0050b8728cc83ed1b996ce9005d4c36",
                                "ff856a2d251dcd88d36656f450126798cfabaade40799c722de4d2b5db36a73a"
                            ]
                        },
                        {
                            "sha256fp": [
                                "44336eb05c6c783dc177217a9f6fef75f4524e98045b390803ae9de69eb42b08",
                                "3c35cc963eb004451323d3275d05b353235053490d9cd83729a2faf5e7ca1cc0",
                                "08297a4047dba23680c731db6e317653ca7848e1bebd3a0b0179a707f92cf178"
                            ]
                        }
                    ],
                    "ever_valid": true,
                    "had_trusted_path": true,
                    "parents": [
                        "44336eb05c6c783dc177217a9f6fef75f4524e98045b390803ae9de69eb42b08",
                        "9f630426df1d8abfd80ace98871ba833ab9742cb34838de2b5285ed54c0c7dcc",
                        "a4124fdaf9cac7baee1cab32e3225d746500c09f3cf3ebb253ef3fbb088afd34",
                        "c3f697a92a293d86f9a3ee7ccb970e20e0050b8728cc83ed1b996ce9005d4c36"
                    ],
                    "type": "leaf"
                },
                "nss": {}
            },
            "validation_level": "ov",
            "zlint": {
                "failed_lints": [
                    "n_subject_common_name_included",
                    "w_ext_key_usage_not_critical"
                ],
                "notices_present": true,
                "timestamp": "2023-09-09T05:55:46Z",
                "version": 3,
                "warnings_present": true
            }
        }
    }
}
```

#### Human Readable Output

>### Information for certificate
>
>|Added At|Browser Trust|Modified At|SHA 256|Validated At|
>|---|---|---|---|---|
>| 1970-01-01T00:00:00Z | nss: Invalid,<br/>microsoft: Valid,<br/>apple: Valid,<br/>chrome: Invalid | 2024-01-23T12:12:35Z | 9d3b51a6b80daf76e074730f19dc01e643ca0c3127d8f48be64cf3302f6622cc | 2023-09-09T05:55:46Z |

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
>
>|Issuer|Issuer DN|Names|SHA256|Subject DN|Validity|
>|---|---|---|---|---|---|
>| organization: Let's Encrypt | C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3 | *.45g4rg43g4fr3434g.gb.net,<br/>45g4rg43g4fr3434g.gb.net | f3ade17dffcadd9532aeb2514f10d66e22941393725aa65366ac286df9b442ec | CN=45g4rg43g4fr3434g.gb.net | start: 2020-10-12T14:46:11Z<br/>end: 2021-01-10T14:46:11Z |

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
| Censys.IP.services.protocol | String | The name of the service running on the IP. |
| Censys.IP.services.cert | String | The SSL/TLS certificate associated with the service running on the IP. |
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
>
>| **Asn** | **Geo Country** | **Geo Latitude** | **Geo Longitude** | **Ip** | **Port** | **Reputation** | **Updated** |
>| --- | --- | --- | --- | --- | --- | --- |  --- |
>| 15169 | United States | 37.4056 | -122.0775 | 8.8.8.8 | 53, 443, 443, 853 | 0 | 2024-04-14T08:03:28.159Z |
