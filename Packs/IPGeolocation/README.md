# IPGeolocation.io

IP intelligence for Cortex XSOAR, powered by the IPGeolocation.io v3 APIs.

This pack adds IP geolocation, IP security (VPN, proxy, residential proxy, Tor, relay, bot, spam and known attacker
detection), ASN lookup and abuse contact resolution to your SOC automation workflows, and registers
IPGeolocation.io as a Cortex XSOAR IP reputation source.

## What is in this pack

| Content | Name | Purpose |
| --- | --- | --- |
| Integration | IPGeolocation.io | Five commands covering the IP Geolocation, IP Security, Abuse Contact and ASN v3 APIs. |
| Playbook | IPGeolocation.io - IP Enrichment | Reference enrichment flow that scores an IP address, adds Autonomous System context and resolves the abuse contact for adverse verdicts. |

## Commands

| Command | API endpoint | Purpose |
| --- | --- | --- |
| `ip` | `GET /v3/ipgeo` or `GET /v3/security` | IP reputation with a DBotScore, driven by the IP Security threat score and flags. |
| `ipgeolocation-ip-lookup` | `GET /v3/ipgeo` | Full IP or domain lookup covering location, network, ASN, company, currency, country metadata and time zone, plus optional security, abuse, user agent, accuracy, DMA code and hostname modules. |
| `ipgeolocation-ip-security` | `GET /v3/security` | Threat signals only, for anonymizer and abuse detection. |
| `ipgeolocation-abuse-contact` | `GET /v3/abuse` | Abuse contact of the network owner, for abuse reporting and takedown. |
| `ipgeolocation-asn` | `GET /v3/asn` | Autonomous System details including routes, peers, upstreams, downstreams and WHOIS, for infrastructure pivoting and cyber threat hunting. |

## Before you start

You need an IPGeolocation.io API key, created in the
[IPGeolocation.io dashboard](https://app.ipgeolocation.io/login). A paid subscription is required for IP security,
abuse contact and ASN data, and for the optional modules of the geolocation lookup. The base geolocation lookup and
the integration test work on the Free plan.

For configuration steps, credit costs, command reference, error handling, troubleshooting and best practices, see
the integration documentation.
