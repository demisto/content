### Scan completed successfully for 0.0.0.1:443.

### Reputation
|Field|Value|
|---|---|
| Label | BENIGN |
| Score | 42.0 |
| Score Suppressed | false |

### Class Probabilities
|Label|Probability (%)|
|---|---|
| HONEYPOT | 0.31 |
| INACTIVE | 0 |
| BENIGN | 91.15 |
| SUSPICIOUS | 5.68 |
| MALICIOUS | 2.86 |

### Top Signals
|Contribution (%)|Feature|Value|Category|
|---|---|---|---|
| +11.92 | Any Threat | false | threat_intelligence |
| +10.86 | Distinct Threats | 0 | threat_intelligence |
| -6.58 | Max Port | 853 | service_surface |

### Enriched Host Data
|IP|Labels|Service Count|Service Ports|Service Protocols|Service Transport Protocols|Service Labels|Service Vulns|Service Threats|Service Scan Times|DNS Names|Forward DNS Names|Reverse DNS Names|Network Name|CIDRs|Autonomous System Name|Autonomous System ASN|City|Province|Postal Code|Country|Country Code|Continent|Latitude|Longitude|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0.0.0.1 | CLOUD_PROVIDER, WEB_SERVER | 3 | 22 | SSH | tcp | REMOTE_ACCESS | CVE-2023-12345, CVE-2023-67890 | BRUTE_FORCE_ATTACK | 2026-02-02T00:46:23Z | example.com, www.example.com | example.com, www.example.com, mail.example.com | host.example.com | EXAMPLE LIMITED | 0.0.0.1/24 | EXAMPLE-AS-AP Example.Co.LTD | 12345 | Seoul | Seoul | 03141 | South Korea | KR | Asia | 37.566 | 126.9784 |

### GreyNoise
|Classification|Threat Actor|Last Seen Scanned|
|---|---|---|
| malicious | Generic Actor | 2026-01-14T13:32:45Z |

### IP Info
|Network Hosting|Network Mobile|Network Satellite|Privacy Anonymous|Privacy Tor|Privacy Proxy|Privacy Relay|Privacy VPN|
|---|---|---|---|---|---|---|---|
| true | false | false | true | false | false | false | true |

### Mallory
|Name|Type|First Seen At|Last Seen At|Last Update At|Description|Verdict|Confidence|Source|Source Count|Tags|
|---|---|---|---|---|---|---|---|---|---|---|
| 0.0.0.1 | ip.v4 | 2026-07-10T00:00:00Z | 2026-07-22T13:48:19Z | 2026-07-22T13:48:19Z | Generic description for the observable. | malicious: 1, suspicious: 1 | high, medium | generic_source_one, generic_source_two | 2 | c2, dns, scanner |
