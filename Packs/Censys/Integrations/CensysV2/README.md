Built on the industry’s most comprehensive Internet Map, the Censys Platform delivers unmatched visibility into global internet assets, adversary infrastructure, and evolving threats.
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
| Censys.Search.parsed.subject.common_name | Unknown | Common name\(s\) from the certificate subject. |
| Censys.Search.parsed.signature.self_signed | Boolean | Whether the certificate is self-signed. |
| Censys.Search.valid_to | String | Timestamp of when the certificate is valid to. |
| Censys.Search.self_signed | Boolean | Whether the certificate is self-signed. |

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
| port | A comma-separated ports associated with the domain. Default is 80, 443. | Optional |

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
| Censys.Domain.hostname | String | The hostname of the web property associated with the domain. |
| Censys.Domain.port | Number | The port number of the web property associated with the domain. |
| Censys.Domain.labels.value | String | Labels associated with the web property. |
| Censys.Domain.threats.name | String | Threat names associated with the web property. |
| Censys.Domain.vulns.id | String | Vulnerability IDs associated with the web property. |
| Censys.Domain.vulns.cvss | Number | CVSS scores for vulnerabilities associated with the web property. |
| Censys.Domain.vulns.severity | String | Severity levels for vulnerabilities associated with the web property. |
| Censys.Domain.software.vendor | String | Software vendors detected on the web property. |
| Censys.Domain.software.product | String | Software products detected on the web property. |
| Censys.Domain.software.version | String | Software versions detected on the web property. |
| Censys.Domain.cert.fingerprint_sha256 | String | SHA-256 fingerprint of the certificate associated with the web property. |
| Censys.Domain.cert.parsed.subject_dn | String | Subject DN of the certificate associated with the web property. |
| Censys.Domain.cert.parsed.issuer_dn | String | Issuer DN of the certificate associated with the web property. |
| Censys.Domain.tls.version_selected | String | TLS version selected for the web property. |
| Censys.Domain.tls.cipher_selected | String | Cipher suite selected for the web property. |
| Censys.Domain.endpoints.endpoint_type | String | Endpoint types associated with the web property. |
| Censys.Domain.endpoints.path | String | Endpoint paths associated with the web property. |
| Censys.Domain.jarm.fingerprint | String | JARM fingerprint of the web property. |
| Censys.Domain.scan_time | String | Scan time for the web property. |
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

>### Censys results for Domain amazon.com
>
>### Enriched Web Property Data
>
>|Hostname|Port|Scan Time|Endpoint Types|Endpoint Paths|Labels|Threat Names|Vulns Names|Vendors|Products|Versions|sha256|Subject DN|Issuer DN|Common Names|Not Before|Not After|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| amazon.com | 443 | 2026-03-10T07:52:06Z | HTTP | / | WEB_SERVER, HTTPS | OUTDATED_SOFTWARE | CVE-2024-11111 | f5 | nginx | 1.18.0 | 0000000000000000000000000000000000000000000000000000000000000001 | CN=example.com | C=US, O=Let's Encrypt, CN=R11 | example.com | 2025-01-03T04:11:45Z | 2025-04-03T04:11:44Z |
>
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
| Censys.IP.services.port | Number | The port number associated with the service running on the IP. |
| Censys.IP.services.transport_protocol | String | The transport protocol used by the service running on the IP. |
| Censys.IP.services.protocol | String | The name of the service running on the IP. |
| Censys.IP.services.cert | String | The SSL/TLS certificate associated with the service running on the IP. |
| Censys.IP.labels | String | Labels associated with the IP address (with premium access only). |
| Censys.IP.dns.reverse_dns.names | String | Reverse DNS names associated with the IP address. |
| Censys.IP.autonomous_system.country_code | String | The country code of the autonomous system associated with the IP address. |
| Censys.IP.autonomous_system.description | String | Description of the autonomous system associated with the IP address. |
| Censys.IP.autonomous_system.name | String | Name of the autonomous system associated with the IP address. |
| Censys.IP.autonomous_system.bgp_prefix | String | BGP prefix of the autonomous system associated with the IP address. |
| Censys.IP.autonomous_system.asn | Number | Autonomous System Number \(ASN\) of the autonomous system associated with the IP address. |
| Censys.IP.ip | String | The IP address. |
| Censys.IP.location.country | String | Country name of the location associated with the IP address. |
| Censys.IP.location.timezone | String | Time zone of the location associated with the IP address. |
| Censys.IP.location.province | String | Province name of the location associated with the IP address. |
| Censys.IP.location.coordinates.latitude | Number | Latitude coordinate of the location associated with the IP address. |
| Censys.IP.location.coordinates.longitude | Number | Longitude coordinate of the location associated with the IP address. |
| Censys.IP.location.continent | String | Continent name of the location associated with the IP address. |
| Censys.IP.location.postal_code | String | Postal code of the location associated with the IP address. |
| Censys.IP.location.city | String | City name of the location associated with the IP address. |
| Censys.IP.location.country_code | String | Country code of the location associated with the IP address. |
| Censys.IP.service_count | Number | The total number of services running on the IP address. |
| Censys.IP.services.labels.value | String | Labels associated with services running on the IP address. |
| Censys.IP.services.threats.name | String | Threat names associated with services running on the IP address. |
| Censys.IP.services.vulns | String | Vulnerabilities associated with services running on the IP address. |
| Censys.IP.services.scan_time | String | Scan time for services running on the IP address. |
| Censys.IP.dns.names | String | DNS names associated with the IP address. |
| Censys.IP.dns.forward_dns.names | String | Forward DNS names associated with the IP address. |
| Censys.IP.whois.network.name | String | WHOIS network name associated with the IP address. |
| Censys.IP.whois.network.cidrs | String | WHOIS network CIDR blocks associated with the IP address. |
| IP.Address | unknown | The IP address. |
| IP.ASN | unknown | The IP ASN. |
| IP.Geo.Country | unknown | The IP country. |
| IP.Geo.Location | unknown | The IP location. |
| IP.UpdatedDate | unknown | The IP last update. |
| IP.Port | unknown | The IP port. |
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

>### Censys results for IP: 8.8.8.8
>
>### Enriched Host Data
>
>|IP|Labels|Service Count|Service Ports|Service Protocols|Service Transport Protocols|Reverse DNS Names|Autonomous System Name|Autonomous System ASN|City|Province|Postal Code|Country|Country Code|Continent|Latitude|Longitude|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 8.8.8.8 | database, email, file-sharing, iot, login-page | 4 | 53, 443, 443, 853 | DNS, HTTP, UNKNOWN, UNKNOWN | UDP, TCP, QUIC, TCP | dns.google | GOOGLE | 15169 | Mountain View | California | 94043 | United States | US | North America | 37.4056 | -122.0775 |

### cen-host-history-list

***
Retrieve the event history for a host (IP address).

#### Base Command

`cen-host-history-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| host_id | Specify the IP address of a host. | Required |
| start_time | Specify the start time of the host timeline.<br/><br/>Supported date formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 Jan 2026, 01 Jan 2026 04:45:33, 2026-01-10T14:05:44Z. | Required |
| end_time | Specify the end time of the host timeline.<br/><br/>Supported date formats: 2 minutes, 2 hours, 2 days, 2 weeks, 2 months, 2 years, yyyy-mm-dd, yyyy-mm-ddTHH:MM:SSZ.<br/><br/>For example: 01 Jan 2026, 01 Jan 2026 04:45:33, 2026-01-10T14:05:44Z. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Censys.HostEventHistory.ip | String | The IP address of the host. |
| Censys.HostEventHistory.total_events | Number | The total number of events associated with the host. |
| Censys.HostEventHistory.partial_data | Boolean | Whether the data is partial or not. |
| Censys.HostEventHistory.events.resource.service_scanned.scan.scan_time | Date | The timestamp when the service scan was performed. |
| Censys.HostEventHistory.events.resource.service_scanned.scan.ip | String | The IP address of the scanned service. |
| Censys.HostEventHistory.events.resource.service_scanned.scan.port | Number | The port number of the scanned service. |
| Censys.HostEventHistory.events.resource.service_scanned.scan.protocol | String | The protocol used by the scanned service. |
| Censys.HostEventHistory.events.resource.service_scanned.scan.transport_protocol | String | The transport protocol used during the service scan. |
| Censys.HostEventHistory.events.resource.service_scanned.scan.is_success | Boolean | Whether the service scan was successful or not. |
| Censys.HostEventHistory.events.resource.service_scanned.scan.mysql.error_code | Number | The MySQL error code returned during the scan. |
| Censys.HostEventHistory.events.resource.service_scanned.scan.mysql.error_id | String | The MySQL error identifier returned during the scan. |
| Censys.HostEventHistory.events.resource.service_scanned.scan.mysql.error_message | String | The MySQL error message returned during the scan. |
| Censys.HostEventHistory.events.resource.forward_dns_resolved.name | String | The domain name resolved from the forward DNS lookup. |
| Censys.HostEventHistory.events.resource.forward_dns_resolved.resolve_time | String | The timestamp when the forward DNS resolution occurred. |
| Censys.HostEventHistory.events.resource.jarm_scanned.diff.additionalProp.new | String | The new value in the JARM scan difference. |
| Censys.HostEventHistory.events.resource.jarm_scanned.diff.additionalProp.old | String | The old value in the JARM scan difference. |
| Censys.HostEventHistory.events.resource.jarm_scanned.scan.cipher_and_version_fingerprint | String | The cipher and version fingerprint from the JARM scan. |
| Censys.HostEventHistory.events.resource.jarm_scanned.scan.fingerprint | String | The JARM fingerprint of the scanned service. |
| Censys.HostEventHistory.events.resource.jarm_scanned.scan.hostname | String | The hostname used in the JARM scan. |
| Censys.HostEventHistory.events.resource.jarm_scanned.scan.ip | String | The IP address scanned by JARM. |
| Censys.HostEventHistory.events.resource.jarm_scanned.scan.is_success | Boolean | Whether the JARM scan was successful or not. |
| Censys.HostEventHistory.events.resource.jarm_scanned.scan.port | Number | The port number scanned by JARM. |
| Censys.HostEventHistory.events.resource.jarm_scanned.scan.scan_time | String | The timestamp when the JARM scan was performed. |
| Censys.HostEventHistory.events.resource.jarm_scanned.scan.tls_extensions_sha256 | String | The SHA-256 hash of the TLS extensions from the JARM scan. |
| Censys.HostEventHistory.events.resource.jarm_scanned.scan.transport_protocol | String | The transport protocol used during the JARM scan. |
| Censys.HostEventHistory.events.resource.location_updated.location.city | String | The city where the host is located. |
| Censys.HostEventHistory.events.resource.location_updated.location.continent | String | The continent where the host is located. |
| Censys.HostEventHistory.events.resource.location_updated.location.coordinates.latitude | Number | The latitude coordinate of the host location. |
| Censys.HostEventHistory.events.resource.location_updated.location.coordinates.longitude | Number | The longitude coordinate of the host location. |
| Censys.HostEventHistory.events.resource.location_updated.location.country | String | The country where the host is located. |
| Censys.HostEventHistory.events.resource.location_updated.location.country_code | String | The country code where the host is located. |
| Censys.HostEventHistory.events.resource.location_updated.location.postal_code | String | The postal code of the host location. |
| Censys.HostEventHistory.events.resource.location_updated.location.province | String | The province or state where the host is located. |
| Censys.HostEventHistory.events.resource.location_updated.location.registered_country | String | The registered country of the host. |
| Censys.HostEventHistory.events.resource.location_updated.location.registered_country_code | String | The registered country code of the host. |
| Censys.HostEventHistory.events.resource.location_updated.location.timezone | String | The timezone of the host location. |
| Censys.HostEventHistory.events.resource.reverse_dns_resolved.names | String | The domain names resolved from the reverse DNS lookup. |
| Censys.HostEventHistory.events.resource.reverse_dns_resolved.resolve_time | String | The timestamp when the reverse DNS resolution occurred. |
| Censys.HostEventHistory.events.resource.route_updated.diff.additionalProp.new | String | The new value in the route update difference. |
| Censys.HostEventHistory.events.resource.route_updated.diff.additionalProp.old | String | The old value in the route update difference. |
| Censys.HostEventHistory.events.resource.route_updated.route.asn | Number | The Autonomous System Number of the route. |
| Censys.HostEventHistory.events.resource.route_updated.route.bgp_prefix | String | The BGP prefix of the route. |
| Censys.HostEventHistory.events.resource.route_updated.route.country_code | String | The country code associated with the route. |
| Censys.HostEventHistory.events.resource.route_updated.route.description | String | The description of the route. |
| Censys.HostEventHistory.events.resource.route_updated.route.name | String | The name of the route. |
| Censys.HostEventHistory.events.resource.route_updated.route.organization | String | The organization associated with the route. |
| Censys.HostEventHistory.events.resource.whois_updated.diff.additionalProp.new | String | The new value in the WHOIS update difference. |
| Censys.HostEventHistory.events.resource.whois_updated.diff.additionalProp.old | String | The old value in the WHOIS update difference. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.network.allocation_type | String | The allocation type of the network in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.network.cidrs | String | The CIDR blocks of the network in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.network.created | String | The creation timestamp of the network in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.network.handle | String | The handle identifier of the network in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.network.name | String | The name of the network in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.network.updated | String | The last update timestamp of the network in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.organization.abuse_contacts.email | String | The email address of the abuse contact in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.organization.abuse_contacts.handle | String | The handle identifier of the abuse contact in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.organization.abuse_contacts.name | String | The name of the abuse contact in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.organization.address | String | The address of the organization in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.organization.admin_contacts.email | String | The email address of the admin contact in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.organization.admin_contacts.handle | String | The handle identifier of the admin contact in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.organization.admin_contacts.name | String | The name of the admin contact in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.organization.city | String | The city of the organization in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.organization.country | String | The country of the organization in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.organization.handle | String | The handle identifier of the organization in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.organization.name | String | The name of the organization in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.organization.postal_code | String | The postal code of the organization in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.organization.state | String | The state or province of the organization in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.organization.street | String | The street address of the organization in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.organization.tech_contacts.email | String | The email address of the technical contact in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.organization.tech_contacts.handle | String | The handle identifier of the technical contact in WHOIS data. |
| Censys.HostEventHistory.events.resource.whois_updated.whois.organization.tech_contacts.name | String | The name of the technical contact in WHOIS data. |
| Censys.HostEventHistory.extensions | Unknown | The extensions associated with the host event history. |

#### Command example

```!cen-host-history-list host_id=0.0.0.1 start_time="1 week" end_time="1 day"```

#### Context Example

```json
{
    "Censys": {
        "HostEventHistory": {
            "ip": "0.0.0.1",
            "total_events": 8,
            "partial_data": false,
            "events": [
                {
                    "resource": {
                        "event_time": "2026-03-01T10:00:00.000Z",
                        "service_scanned": {
                            "scan": {
                                "port": 443,
                                "protocol": "https",
                                "transport_protocol": "tcp"
                            }
                        }
                    }
                },
                {
                    "resource": {
                        "event_time": "2026-03-01T09:00:00.000Z",
                        "reverse_dns_resolved": {
                            "names": [
                                "example.com",
                                "www.example.com"
                            ]
                        }
                    }
                },
                {
                    "resource": {
                        "event_time": "2026-03-01T08:00:00.000Z",
                        "endpoint_scanned": {
                            "scan": {
                                "port": 8080,
                                "endpoint_type": "http"
                            }
                        }
                    }
                },
                {
                    "resource": {
                        "event_time": "2026-03-01T07:00:00.000Z",
                        "forward_dns_resolved": {
                            "name": "test.example.com"
                        }
                    }
                },
                {
                    "resource": {
                        "event_time": "2026-03-01T06:00:00.000Z",
                        "jarm_scanned": {
                            "scan": {
                                "port": 443,
                                "fingerprint": "0000000000000000000000000000000000000000000000000000000000001"
                            }
                        }
                    }
                },
                {
                    "resource": {
                        "event_time": "2026-03-01T05:00:00.000Z",
                        "location_updated": {
                            "location": {
                                "city": "San Francisco",
                                "country": "United States"
                            }
                        }
                    }
                },
                {
                    "resource": {
                        "event_time": "2026-03-01T04:00:00.000Z",
                        "route_updated": {
                            "route": {
                                "asn": "15169",
                                "organization": "Google LLC"
                            }
                        }
                    }
                },
                {
                    "resource": {
                        "event_time": "2026-03-01T03:00:00.000Z",
                        "whois_updated": {
                            "whois": {
                                "organization": {
                                    "name": "Example Organization"
                                }
                            }
                        }
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Successfully retrieved 8 event(s) for host 0.0.0.1
>
>### Host History Events
>
>|Event Time|Resource Type|Resource Details|Link to Censys|
>|---|---|---|---|
>| 2026-03-01T10:00:00.000Z | service_scanned | 443/TCP/https | [View historical host on Censys platform](https://platform.censys.io/hosts/0.0.0.1?at_time=2026-03-01T10:00:00.000Z) |
>| 2026-03-01T09:00:00.000Z | reverse_dns_resolved | example.com | [View historical host on Censys platform](https://platform.censys.io/hosts/0.0.0.1?at_time=2026-03-01T09:00:00.000Z) |
>| 2026-03-01T08:00:00.000Z | endpoint_scanned | 8080/http | [View historical host on Censys platform](https://platform.censys.io/hosts/0.0.0.1?at_time=2026-03-01T08:00:00.000Z) |
>| 2026-03-01T07:00:00.000Z | forward_dns_resolved | test.example.com | [View historical host on Censys platform](https://platform.censys.io/hosts/0.0.0.1?at_time=2026-03-01T07:00:00.000Z) |
>| 2026-03-01T06:00:00.000Z | jarm_scanned | 443/0000000000000000000000000000000000000000000000000000000000001 | [View historical host on Censys platform](https://platform.censys.io/hosts/0.0.0.1?at_time=2026-03-01T06:00:00.000Z) |
>| 2026-03-01T05:00:00.000Z | location_updated | San Francisco/United States | [View historical host on Censys platform](https://platform.censys.io/hosts/0.0.0.1?at_time=2026-03-01T05:00:00.000Z) |
>| 2026-03-01T04:00:00.000Z | route_updated | 15169/Google LLC | [View historical host on Censys platform](https://platform.censys.io/hosts/0.0.0.1?at_time=2026-03-01T04:00:00.000Z) |
>| 2026-03-01T03:00:00.000Z | whois_updated | Example Organization | [View historical host on Censys platform](https://platform.censys.io/hosts/0.0.0.1?at_time=2026-03-01T03:00:00.000Z) |

### cen-rescan

***
Initiate a live rescan for a known host service at a specific IP and port (ip:port) or hostname and port (hostname:port).

#### Base Command

`cen-rescan`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_type | Specify the type of IOC. Possible values are: Service, Web Property. Default is Service. | Required |
| ioc_value | Specify the value of IOC. | Required |
| port | Specify the port number associated with the IOC. Default is 443. | Required |
| protocol | Specify the service protocol.<br/><br/>Note:This argument is required only if the IOC type is Service. | Optional |
| transport_protocol | Specify the transport protocol.<br/><br/>Note: This argument is required only if the IOC type is Service. Possible values are: Unknown, TCP, UDP, ICMP, QUIC. Default is Unknown. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Censys.Rescan.scan_id | String | The unique identifier for the rescan operation. |
| Censys.Rescan.status | String | The status of the rescan \(initiated, in_progress, completed, failed\). |
| Censys.Rescan.is_completed | Boolean | Whether the rescan has completed. |
| Censys.Rescan.enrichment_data.ip | String | The IP address of the rescanned host. |
| Censys.Rescan.enrichment_data.service_count | Number | The total number of services detected on the host. |
| Censys.Rescan.enrichment_data.labels | Unknown | Labels associated with the host. |
| Censys.Rescan.enrichment_data.location.continent | String | The continent of the host's detected location. |
| Censys.Rescan.enrichment_data.location.country | String | The name of the country of the host's detected location. |
| Censys.Rescan.enrichment_data.location.country_code | String | The two-letter ISO 3166-1 alpha-2 country code of the host's detected location. |
| Censys.Rescan.enrichment_data.location.city | String | The city of the host's detected location. |
| Censys.Rescan.enrichment_data.location.province | String | The province or state of the host's detected location. |
| Censys.Rescan.enrichment_data.location.postal_code | String | The postal code of the host's detected location. |
| Censys.Rescan.enrichment_data.location.timezone | String | The timezone of the host's detected location. |
| Censys.Rescan.enrichment_data.location.coordinates.latitude | Number | The latitude of the host's detected location. |
| Censys.Rescan.enrichment_data.location.coordinates.longitude | Number | The longitude of the host's detected location. |
| Censys.Rescan.enrichment_data.autonomous_system.asn | Number | The autonomous system number \(ASN\) that the host is in. |
| Censys.Rescan.enrichment_data.autonomous_system.description | String | A brief description of the autonomous system. |
| Censys.Rescan.enrichment_data.autonomous_system.bgp_prefix | String | The autonomous system's CIDR. |
| Censys.Rescan.enrichment_data.autonomous_system.name | String | The friendly name of the autonomous system. |
| Censys.Rescan.enrichment_data.autonomous_system.country_code | String | The autonomous system's two-letter, ISO 3166-1 alpha-2 country code. |
| Censys.Rescan.enrichment_data.whois.network.handle | String | The WHOIS network handle identifier. |
| Censys.Rescan.enrichment_data.whois.network.name | String | The WHOIS network name. |
| Censys.Rescan.enrichment_data.whois.network.cidrs | Unknown | The WHOIS network CIDRs. |
| Censys.Rescan.enrichment_data.whois.network.created | Date | The creation date of the WHOIS network record. |
| Censys.Rescan.enrichment_data.whois.network.updated | Date | The last update date of the WHOIS network record. |
| Censys.Rescan.enrichment_data.whois.organization.handle | String | The WHOIS organization handle identifier. |
| Censys.Rescan.enrichment_data.whois.organization.name | String | The WHOIS organization name. |
| Censys.Rescan.enrichment_data.whois.organization.address | String | The WHOIS organization address. |
| Censys.Rescan.enrichment_data.whois.organization.abuse_contacts | Unknown | The WHOIS organization abuse contacts. |
| Censys.Rescan.enrichment_data.whois.organization.admin_contacts | Unknown | The WHOIS organization admin contacts. |
| Censys.Rescan.enrichment_data.services | Unknown | List of services detected on the host. |
| Censys.Rescan.enrichment_data.services.port | Number | The port the service was reached at. |
| Censys.Rescan.enrichment_data.services.protocol | String | The name of the service on the port. |
| Censys.Rescan.enrichment_data.services.transport_protocol | String | The transport protocol used to contact this service. |
| Censys.Rescan.enrichment_data.services.software | Unknown | Software identified on the service. |
| Censys.Rescan.enrichment_data.services.software.source | String | The source of the software identification. |
| Censys.Rescan.enrichment_data.services.software.confidence | Number | The confidence level of the software identification. |
| Censys.Rescan.enrichment_data.services.software.part | String | The part classification of the software in CPE format. |
| Censys.Rescan.enrichment_data.services.software.vendor | String | The vendor of the identified software. |
| Censys.Rescan.enrichment_data.services.software.product | String | The product name of the identified software. |
| Censys.Rescan.enrichment_data.services.labels | Unknown | Labels associated with the service. |
| Censys.Rescan.enrichment_data.services.labels.value | String | The value of the service label. |
| Censys.Rescan.enrichment_data.services.threats | Unknown | Threats detected on the service. |
| Censys.Rescan.enrichment_data.services.vulns | Unknown | Vulnerabilities detected on the service. |
| Censys.Rescan.enrichment_data.services.ip | String | The IP address of the service. |
| Censys.Rescan.enrichment_data.services.scan_time | Date | The time when the service was scanned. |
| Censys.Rescan.enrichment_data.services.banner | String | The banner returned by the service. |
| Censys.Rescan.enrichment_data.services.banner_hash_sha256 | String | The SHA-256 hash of the service banner. |
| Censys.Rescan.enrichment_data.services.banner_hex | String | The hexadecimal representation of the service banner. |
| Censys.Rescan.enrichment_data.dns.reverse_dns.resolve_time | Date | The time when reverse DNS was resolved. |
| Censys.Rescan.enrichment_data.dns.names | Unknown | DNS names associated with the host. |
| Censys.Rescan.enrichment_data.dns.forward_dns.names | Unknown | Forward DNS names for the host. |
| Censys.Rescan.enrichment_data.dns.reverse_dns.names | Unknown | Reverse DNS names for the host. |
| IP.Address | String | The IP address. |
| IP.ASN | String | The autonomous system name for the IP address, for example: "AS8948". |
| IP.Geo.Location | String | The geolocation where the IP address is located, in the format: latitude:longitude. |
| IP.Geo.Country | String | The country in which the IP address is located. |
| IP.Geo.Description | String | Additional information about the location. |
| IP.ASOwner | String | The autonomous system owner of the IP. |
| IP.Port | String | Ports that are associated with the IP. |
| IP.Malicious.Vendor | String | The vendor reporting the IP address as malicious. |
| IP.Malicious.Description | String | A description explaining why the IP address was reported as malicious. |
| Domain.Name | String | The domain name, for example: "google.com". |
| Domain.Malicious.Vendor | String | The vendor reporting the domain as malicious. |
| Domain.Malicious.Description | String | A description explaining why the domain was reported as malicious. |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |

#### Command example

```!cen-rescan ioc_type="Service" ioc_value="0.0.0.1" port="443" protocol="HTTPS" transport_protocol="TCP"```

#### Context Example

```json
{
    "Censys": {
        "Rescan": {
            "ioc_value": "0.0.0.1",
            "port": 443,
            "status": "completed",
            "scan_id": "00000000-0000-0000-0000-000000000001",
            "is_completed": true,
            "enrichment_data": {
                "ip": "0.0.0.1",
                "labels": [
                    {
                        "source": "censys",
                        "value": "CLOUD_PROVIDER"
                    },
                    {
                        "source": "censys",
                        "value": "WEB_SERVER"
                    }
                ],
                "location": {
                    "continent": "Asia",
                    "country": "South Korea",
                    "country_code": "KR",
                    "city": "Seoul",
                    "postal_code": "03141",
                    "timezone": "Asia/Seoul",
                    "province": "Seoul",
                    "coordinates": {
                        "latitude": 37.566,
                        "longitude": 126.9784
                    }
                },
                "autonomous_system": {
                    "asn": 12345,
                    "description": "EXAMPLE-AS-AP Example.Co.LTD",
                    "bgp_prefix": "0.0.0.1/24",
                    "name": "EXAMPLE-AS-AP Example.Co.LTD",
                    "country_code": "KR"
                },
                "whois": {
                    "network": {
                        "handle": "HK-EXAMPLE-20190703",
                        "name": "EXAMPLE LIMITED",
                        "cidrs": [
                            "0.0.0.1/24"
                        ],
                        "created": "2024-11-26T00:00:00Z",
                        "updated": "2025-08-18T00:00:00Z"
                    },
                    "organization": {
                        "handle": "ORG-XL117-RIPE",
                        "name": "EXAMPLE LIMITED",
                        "address": "RM 29-33,5/F,EXAMPLE COMMERCIAL CENTRE,87-105 EXAMPLE ROAD\\n000000\\nEXAMPLE CITY\\nEXAMPLE COUNTRY",
                        "abuse_contacts": [
                            {
                                "handle": "EXAMPLE-RIPE",
                                "name": "EXAMPLE-ROLE",
                                "email": "noc@example.com"
                            }
                        ],
                        "admin_contacts": [
                            {
                                "handle": "EXAMPLE-RIPE",
                                "name": "EXAMPLE-ROLE",
                                "email": "noc@example.com"
                            }
                        ]
                    }
                },
                "services": [
                    {
                        "port": 22,
                        "protocol": "SSH",
                        "transport_protocol": "tcp",
                        "software": [
                            {
                                "source": "censys",
                                "confidence": 0.9,
                                "evidence": [
                                    {
                                        "data_path": "protocol",
                                        "found_value": "SSH",
                                        "literal_match": "SSH"
                                    }
                                ],
                                "type": [
                                    "REMOTE_ACCESS"
                                ],
                                "part": "a"
                            }
                        ],
                        "labels": [
                            {
                                "source": "censys",
                                "confidence": 0.9,
                                "evidence": [
                                    {
                                        "data_path": "protocol",
                                        "found_value": "SSH",
                                        "literal_match": "SSH"
                                    }
                                ],
                                "value": "REMOTE_ACCESS"
                            }
                        ],
                        "threats": [
                            {
                                "name": "BRUTE_FORCE_ATTACK",
                                "source": "censys"
                            }
                        ],
                        "vulns": [
                            {
                                "id": "CVE-2023-12345",
                                "cvss": 7.5,
                                "severity": "HIGH"
                            },
                            {
                                "id": "CVE-2023-67890",
                                "cvss": 5.3,
                                "severity": "MEDIUM"
                            }
                        ],
                        "ip": "0.0.0.1",
                        "scan_time": "2026-02-02T00:46:23Z",
                        "banner": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
                        "banner_hash_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                        "banner_hex": "5353482d322e302d4f70656e5353485f392e3270312044656269616e2d322b64656231327533",
                        "ja4tscan": {
                            "scan_time": "2026-02-01T17:09:57Z",
                            "fingerprint": "65160_2-4-8-1-3_1460_7_1-2-4-8-16"
                        },
                        "ssh": {
                            "endpoint_id": {
                                "raw": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
                                "protocol_version": "2.0",
                                "software_version": "OpenSSH_9.2p1",
                                "comment": "Debian-2+deb12u3"
                            },
                            "kex_init_message": {
                                "kex_algorithms": [
                                    "example@openssh.com",
                                    "curve25519-sha256",
                                    "example@openssh.com"
                                ],
                                "host_key_algorithms": [
                                    "rsa-sha2-512",
                                    "rsa-sha2-256",
                                    "ecdsa-sha2-nistp256",
                                    "ssh-ed25519"
                                ],
                                "client_to_server_ciphers": [
                                    "example@openssh.com",
                                    "aes128-ctr"
                                ],
                                "server_to_client_ciphers": [
                                    "example@openssh.com",
                                    "aes128-ctr"
                                ],
                                "client_to_server_macs": [
                                    "example@openssh.com",
                                    "example@openssh.com"
                                ],
                                "server_to_client_macs": [
                                    "example@openssh.com",
                                    "example@openssh.com"
                                ],
                                "client_to_server_compression": [
                                    "none",
                                    "example@openssh.com"
                                ],
                                "server_to_client_compression": [
                                    "none",
                                    "example@openssh.com"
                                ]
                            },
                            "algorithm_selection": {
                                "kex_algorithm": "example@libssh.org",
                                "host_key_algorithm": "ecdsa-sha2-nistp256",
                                "client_to_server_cipher": "example@openssh.com",
                                "server_to_client_cipher": "example@openssh.com",
                                "client_to_server_mac": "example@openssh.com",
                                "server_to_client_mac": "example@openssh.com",
                                "client_to_server_compression": "none",
                                "server_to_client_compression": "none"
                            },
                            "server_host_key": {
                                "ecdsa_public_key": {
                                    "b": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                                    "curve": "P256",
                                    "gx": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                                    "gy": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                                    "length": 256,
                                    "n": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                                    "p": "/////wAAAAEAAAAAAAAAAAAAAAD///////////////8=",
                                    "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                                    "y": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                                }
                            },
                            "hassh_fingerprint": "00000000000000000000000000000000"
                        }
                    }
                ],
                "service_count": 3,
                "dns": {
                    "names": [
                        "example.com",
                        "www.example.com"
                    ],
                    "forward_dns": {
                        "names": [
                            "example.com",
                            "www.example.com",
                            "mail.example.com"
                        ]
                    },
                    "reverse_dns": {
                        "names": [
                            "host.example.com"
                        ],
                        "resolve_time": "2026-01-30T18:11:14Z"
                    }
                }
            }
        }
    }
}
```

#### Human Readable Output

>### Scan completed successfully for 0.0.0.1:443
>
>### Enriched Host Data
>
>|IP|Labels|Service Count|Service Ports|Service Protocols|Service Transport Protocols|Service Labels|Service Vulns|Service Threats|Service Scan Times|DNS Names|Forward DNS Names|Reverse DNS Names|Network Name|CIDRs|Autonomous System Name|Autonomous System ASN|City|Province|Postal Code|Country|Country Code|Continent|Latitude|Longitude|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 0.0.0.1 | CLOUD_PROVIDER, WEB_SERVER | 3 | 22 | SSH | tcp | REMOTE_ACCESS | CVE-2023-12345, CVE-2023-67890 | BRUTE_FORCE_ATTACK | 2026-02-02T00:46:23Z | example.com, www.example.com | example.com, www.example.com, mail.example.com | host.example.com | EXAMPLE LIMITED | 0.0.0.1/24 | EXAMPLE-AS-AP Example.Co.LTD | 12345 | Seoul | Seoul | 03141 | South Korea | KR | Asia | 37.566 | 126.9784 |

### cen-related-infrastructure-list

***
Initiate a CensEye (Related Infrastructure) pivot analysis job for a Host, Web Property, or SHA256 Certificate.

#### Base Command

`cen-related-infrastructure-list`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ioc_type | Specify the type of IOC. Possible values are: Host, Web Property, Certificate. Default is Host. | Required |
| ioc_value | Specify the value of IOC.<br/><br/>Note: For Web Property IOC type, include the port in the format hostname:port (e.g., example.com:443). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Censys.RelatedInfrastructure.job_id | String | The unique identifier for the related infrastructure job. |
| Censys.RelatedInfrastructure.pivot_data.count | Number | The count of related infrastructure entries for this pivot. |
| Censys.RelatedInfrastructure.pivot_data.field_value_pairs.field | String | The field name of the pivot. |
| Censys.RelatedInfrastructure.pivot_data.field_value_pairs.value | String | The value of the pivot field. |
| Censys.RelatedInfrastructure.status | String | The status of the job \(initiated, in_progress, completed, failed\). |
| Censys.RelatedInfrastructure.is_completed | Boolean | Whether the job has completed. |
| Censys.RelatedInfrastructure.ioc_value | String | The value of the IOC. |

#### Command example

```!cen-related-infrastructure-list ioc_type="Host" ioc_value="0.0.0.1"```

#### Context Example

```json
{
    "Censys": {
        "RelatedInfrastructure": {
            "ioc_value": "0.0.0.1",
            "status": "completed",
            "job_id": "00000000-0000-0000-0000-000000000001",
            "is_completed": true,
            "pivot_data": [
                {
                    "count": 5395,
                    "field_value_pairs": [
                        {
                            "field": "host.services.banner_hash_sha256",
                            "value": "0000000000000000000000000000000000000000000000000000000000000001"
                        }
                    ]
                },
                {
                    "count": 123620,
                    "field_value_pairs": [
                        {
                            "field": "host.services.endpoints.http.headers.key",
                            "value": "Connection"
                        },
                        {
                            "field": "host.services.endpoints.http.headers.value",
                            "value": "close"
                        }
                    ]
                },
                {
                    "count": 5395,
                    "field_value_pairs": [
                        {
                            "field": "host.services.endpoints.banner_hash_sha256",
                            "value": "0000000000000000000000000000000000000000000000000000000000000001"
                        }
                    ]
                },
                {
                    "count": 36216,
                    "field_value_pairs": [
                        {
                            "field": "host.services.endpoints.http.headers.key",
                            "value": "Content-Type"
                        },
                        {
                            "field": "host.services.endpoints.http.headers.value",
                            "value": "text/plain"
                        }
                    ]
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Job completed successfully for 0.0.0.1
>
>### 4 Pivots Data
>
>|Key|Value|Count|See results in Censys|
>|---|---|---|---|
>| host.services.banner_hash_sha256 | 0000000000000000000000000000000000000000000000000000000000000001 | 5395 | [View Pivot Information on Censys platform](https://platform.censys.io/search?q=host.services.banner_hash_sha256+%3D+%220000000000000000000000000000000000000000000000000000000000000001%22) |
>| host.services.endpoints.banner_hash_sha256 | 0000000000000000000000000000000000000000000000000000000000000001 | 5395 | [View Pivot Information on Censys platform](https://platform.censys.io/search?q=host.services.endpoints.banner_hash_sha256+%3D+%220000000000000000000000000000000000000000000000000000000000000001%22) |
>| host.services.endpoints.http.headers.key<br>host.services.endpoints.http.headers.value | Content-Type<br>text/plain | 36216 | [View Pivot Information on Censys platform](https://platform.censys.io/search?q=host.services.endpoints.http.headers%3A+%28key+%3D+%22Content-Type%22+and+value+%3D+%22text%2Fplain%22%29) |
>| host.services.endpoints.http.headers.key<br>host.services.endpoints.http.headers.value | Connection<br>close | 123620 | [View Pivot Information on Censys platform](https://platform.censys.io/search?q=host.services.endpoints.http.headers%3A+%28key+%3D+%22Connection%22+and+value+%3D+%22close%22%29) |
