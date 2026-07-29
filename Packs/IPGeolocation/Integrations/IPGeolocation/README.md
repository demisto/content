# IPGeolocation.io

Enrich IP addresses in Cortex XSOAR with geolocation, network, ASN, abuse contact and threat intelligence data from
the IPGeolocation.io v3 APIs.

This integration was tested with version 3 of the IPGeolocation.io APIs.

## Overview

IPGeolocation.io provides IP intelligence over a small set of focused REST endpoints. This integration exposes four
of them and turns them into Cortex XSOAR commands that can be used directly by an analyst in the war room or called
from a playbook.

The integration is built for three jobs that come up constantly in SOC automation and cyber threat hunting.

1. Answering where an IP address is and which network operates it, for alert triage and impossible travel checks.
2. Answering whether an IP address is hiding behind a VPN, a proxy, a residential proxy, a Tor exit node, a relay or
   a cloud hosting provider, and whether it has been seen behaving like an attacker, a bot or a spam source.
3. Answering who to contact about an IP address, so abuse reporting and takedown requests reach the responsible
   network owner.

The generic `ip` command turns the IP Security signals into a DBotScore, which makes IPGeolocation.io usable as a
Cortex XSOAR IP reputation source in the standard indicator enrichment flow. All other commands are enrichment only
and never write a verdict, so they can be called freely inside investigation logic without changing indicator
reputations.

## Supported APIs

| API | Endpoint | Command | Credits per lookup | Plan |
| --- | --- | --- | --- | --- |
| IP Geolocation API | `GET /v3/ipgeo` | `ipgeolocation-ip-lookup` | 1 for the base lookup, plus 2 when `security` is included and 1 when `abuse` is included | Free plan returns the base response. Domain lookups, non English responses and every optional module require a paid plan. |
| IP Security API | `GET /v3/security` | `ipgeolocation-ip-security` | 2 | Paid plans only. |
| Abuse Contact API | `GET /v3/abuse` | `ipgeolocation-abuse-contact` | 1 | Paid plans only. |
| ASN API | `GET /v3/asn` | `ipgeolocation-asn` | 1 | Paid plans only. |

The generic `ip` reputation command is served by `GET /v3/ipgeo` with `include=security` by default, or by
`GET /v3/security` when geolocation context is disabled on the instance.

No other IPGeolocation.io endpoint is called by this integration. The bulk endpoints (`/v3/ipgeo-bulk` and
`/v3/security-bulk`), the Time Zone API, the User Agent API and the Astronomy API are out of scope for this version.
Commands that accept a list of IP addresses issue one request per address.

## Use Cases

- **Alert triage.** Attach country, city, ASN and hosting context to every external IP address in an incident so an
  analyst can judge relevance in seconds.
- **IP reputation in threat investigation.** Use `!ip` as a reputation provider so phishing, brute force and command
  and control playbooks get a consistent verdict with an auditable reason.
- **Anonymizer detection.** Detect logins and submissions arriving over VPNs, commercial or residential proxies, Tor
  exit nodes and privacy relays, which is a common signal for account takeover and fraud.
- **Cloud and hosting attribution.** Separate traffic that originates from consumer ISPs from traffic that
  originates from cloud or hosting ranges, which changes how a scanning or credential stuffing alert is handled.
- **Cyber threat hunting on infrastructure.** Pivot from an IP address to its Autonomous System, then to the
  announced prefixes, peers and upstream providers, to find neighbouring infrastructure used by the same actor.
- **Abuse reporting and takedown.** Resolve the abuse contact for an offending IP address and route the notification
  automatically.
- **Geofencing and compliance checks.** Confirm whether an access attempt came from a sanctioned or unexpected
  country before a compliance workflow escalates it.

## Prerequisites

- An IPGeolocation.io account and an API key, created in the IPGeolocation.io dashboard.
- Outbound HTTPS access from the Cortex XSOAR server or engine to `api.ipgeolocation.io` on port 443.
- A paid IPGeolocation.io subscription if you intend to use the `ip`, `ipgeolocation-ip-security`,
  `ipgeolocation-abuse-contact` or `ipgeolocation-asn` commands, or any optional module of
  `ipgeolocation-ip-lookup`.

## Configure IPGeolocation.io in Cortex XSOAR

1. Navigate to **Settings** then **Integrations** then **Servers & Services**.
2. Search for **IPGeolocation.io**.
3. Click **Add instance** to create and configure a new integration instance.
4. Complete the parameters below, then click **Test** to validate the connection.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | Base URL of the IPGeolocation.io API. Leave the default unless you route traffic through a gateway. | True |
| API Key | The API key issued in the IPGeolocation.io dashboard. It is sent as the documented `apiKey` query parameter and is masked in Cortex XSOAR logs. | True |
| HTTP timeout (seconds) | Per request timeout, between 1 and 300 seconds. The default is 30. A timeout that is too short causes the API to answer with HTTP 499. | False |
| Trust any certificate (not secure) | Skip TLS certificate verification. Leave this cleared in production. | False |
| Use system proxy settings | Route requests through the proxy configured on the Cortex XSOAR server. | False |
| Source Reliability | Reliability of the source providing the intelligence data. The default is `B - Usually reliable`. | False |
| Include geolocation context in the ip command | When selected, `!ip` calls `/v3/ipgeo` with `include=security` and consumes 3 credits per IP address. When cleared, it calls `/v3/security` and consumes 2 credits per IP address. Selected by default. | False |
| Malicious threat score threshold | Threat score, from 0 to 100, at which `!ip` marks an IP address as Malicious. The default is 70. | False |
| Suspicious threat score threshold | Threat score, from 0 to 100, at which `!ip` marks an IP address as Suspicious. Must be lower than or equal to the malicious threshold. The default is 40. | False |
| Treat known attackers as Malicious | When selected, `is_known_attacker` marks an IP address as Malicious regardless of its threat score. Selected by default. | False |
| Treat anonymizing networks as Suspicious | When selected, a detected VPN, proxy, residential proxy, Tor exit node or relay marks an IP address as Suspicious. Clear this if your own users legitimately connect over a VPN. Selected by default. | False |
| Treat bot and spam activity as Suspicious | When selected, `is_bot` or `is_spam` marks an IP address as Suspicious. Selected by default. | False |

The **Test** button performs a single documented lookup, `GET /v3/ipgeo` for the sample address `8.8.8.8`, and
returns `ok` when the API key is accepted. It works on the Free plan, so a successful test does not by itself prove
that the paid modules are available on your subscription.

## Reputation Scoring

The `ip` command derives its verdict from the IP Security response in a fixed, documented order. The first rule that
matches wins.

1. **Malicious (DBotScore 3)** when the threat score is at or above the malicious threshold, or when
   `is_known_attacker` is true and the corresponding option is enabled.
2. **Suspicious (DBotScore 2)** when the threat score is at or above the suspicious threshold, or when `is_bot` or
   `is_spam` is true, or when any anonymizing signal (`is_tor`, `is_vpn`, `is_proxy`, `is_residential_proxy`,
   `is_relay`) is true, subject to the corresponding options.
3. **Good (DBotScore 1)** when a security object was returned and none of the rules above matched.
4. **Unknown (DBotScore 0)** when the response carried no security object, which is what happens on a Free plan
   subscription. The war room entry explains that a paid subscription is required rather than silently reporting the
   address as clean.

The reason for every verdict is written into the war room entry, and for Malicious verdicts it is also written to
`IP.Malicious.Description`.

## Credits and Rate Limiting

IPGeolocation.io bills per credit rather than per request, and different modules cost different amounts. The credit
cost of every command is listed in the Supported APIs table above, and the exact charge for any single request is
returned by the API in the `X-Credits-Charged` response header.

At the time of writing, IPGeolocation.io applies a hard limit of 1000 requests per day on the Free plan and does not
enforce a per minute, hourly, daily or monthly rate limit on paid plans. Usage above a paid monthly quota continues
to be served and is billed as a surcharge. Consult the IPGeolocation.io pricing page for the surcharge rate that
applies to your plan.

When a quota or surcharge limit is reached, the API answers with HTTP 429 and the integration reports the condition
as a warning against the specific IP address rather than failing the whole command. To control spend, prefer the
following.

- Use `ipgeolocation-ip-security` instead of `ipgeolocation-ip-lookup` with `include=security` when you only need
  threat signals, because the dedicated endpoint costs 2 credits instead of 3.
- Clear **Include geolocation context in the ip command** if your playbooks already enrich geolocation separately.
- Use the `fields` and `excludes` arguments to shrink responses. Note that these arguments reduce payload size and
  parsing time, not the credit cost.
- Enable indicator caching in Cortex XSOAR so repeated enrichment of the same address does not spend credits again.

## Error Handling

Every documented IPGeolocation.io status code is translated into an actionable Cortex XSOAR error that includes the
HTTP status, an explanation and the descriptive `message` field returned by the API.

| HTTP status | Meaning and typical cause |
| --- | --- |
| 400 | Bad Request. The IP address, domain name or ASN is invalid, or an unsupported `lang` value was supplied. |
| 401 | Unauthorized. The API key is missing, invalid, paused, expired or disabled, or the request asked for data that requires a paid plan. |
| 403 | Forbidden. The request was rejected before reaching the API. Check the server URL, Request Origin restrictions and proxy rules. This code is handled defensively and is not part of the documented v3 error tables. |
| 404 | Not Found. The IP address, domain name or ASN is not in the IPGeolocation.io database, or the server URL points at a non-existent endpoint. |
| 405 | Method Not Allowed. Raised if the configured server URL routes the request to an endpoint that rejects GET. |
| 413 | Content Too Large. The request payload exceeded the accepted limit. |
| 415 | Unsupported Media Type. The API rejected the request Content-Type. |
| 423 | Locked. The IP address is a bogon or belongs to a private network. |
| 429 | Too Many Requests. The quota or surcharge limit was reached, or the subscription is past due, deleted or trial expired. |
| 499 | Client Closed Request. The configured HTTP timeout was too short. Increase it in the instance configuration. |
| 500, 502, 503, 504, 505 | Server side error at IPGeolocation.io. Retry, and contact IPGeolocation.io support if it persists. |

Transport level and payload level problems are handled as well.

- Connection failures and connect timeouts are reported as connection errors.
- A read timeout names the configured timeout value so the analyst knows which setting to change.
- An empty response body, a body that is not valid JSON, and a JSON array where an object is documented are each
  reported distinctly, instead of being written into the context as empty data.
- A response that carries only a `message` field, which is how the API reports a bogon or malformed address, is
  surfaced as an error carrying that message.

Commands that accept a list of IP addresses validate and process each address independently. A failure on one
address produces a warning entry for that address and the remaining addresses are still enriched, so a playbook
iterating over a list of indicators is not aborted by a single private or unroutable address. The `ip` command also
short circuits private, loopback, link local and reserved addresses locally, so no credit is spent on an address
that the API would answer with HTTP 423.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook. After you
successfully execute a command, a DBotScore is created and the context is updated.

### ip

Returns the IPGeolocation.io reputation of one or more IP addresses and writes a DBotScore, so the
command can be used anywhere Cortex XSOAR expects a generic IP reputation provider, including automatic indicator
enrichment. The verdict is derived from the IP Security API threat score and detection flags using the thresholds
configured on the instance, and the reasoning is written into the war room entry so an analyst can always see why a
verdict was reached.

This command requires a paid IPGeolocation.io subscription, because IP Security data is not available on the Free
plan. With the default settings it consumes 3 credits per IP address (1 for the geolocation data and 2 for the
security module). Clear **Include geolocation context in the ip command** to fall back to the dedicated Security
endpoint at 2 credits per IP address.

#### Base Command

`ip`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Comma separated list of IPv4 or IPv6 addresses to check. Accepts a comma separated list. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The reputation score, where 0 is Unknown, 1 is Good, 2 is Suspicious and 3 is Bad. |
| DBotScore.Reliability | String | The reliability of the source providing the score. |
| IP.Address | String | The IP address. |
| IP.ASN | String | The Autonomous System Number of the IP address. |
| IP.ASOwner | String | The owner of the Autonomous System. |
| IP.Hostname | String | The reverse DNS hostname of the IP address. |
| IP.Region | String | The region in which the IP address is located. |
| IP.Geo.Location | String | The latitude and longitude of the IP address. |
| IP.Geo.Country | String | The country in which the IP address is located. |
| IP.Geo.Description | String | The city, region and country of the IP address. |
| IP.Organization.Name | String | The organization that owns the IP address. |
| IP.Organization.Type | String | The category of the owning organization. |
| IP.Tags | Unknown | Security signals detected for the IP address, such as vpn or tor. |
| IP.Malicious.Vendor | String | The vendor that flagged the IP address as malicious. |
| IP.Malicious.Description | String | The reason the IP address was flagged as malicious. |
| IPGeolocation.IP.IP | String | The IP address that was looked up. |
| IPGeolocation.IP.Domain | String | The domain name submitted, returned only for domain based lookups. |
| IPGeolocation.IP.Hostname | String | Reverse DNS hostname of the IP address. The API echoes the IP address when no hostname resolves. |
| IPGeolocation.IP.Location.ContinentCode | String | Two letter continent code, for example EU. |
| IPGeolocation.IP.Location.ContinentName | String | Continent name, for example Europe. |
| IPGeolocation.IP.Location.CountryCode2 | String | ISO 3166-1 alpha-2 country code, for example SE. |
| IPGeolocation.IP.Location.CountryCode3 | String | ISO 3166-1 alpha-3 country code, for example SWE. |
| IPGeolocation.IP.Location.CountryName | String | Common country name. |
| IPGeolocation.IP.Location.CountryNameOfficial | String | Official country name, when it differs from the common name. |
| IPGeolocation.IP.Location.CountryCapital | String | Capital city of the country. |
| IPGeolocation.IP.Location.StateProv | String | State, province or region name. |
| IPGeolocation.IP.Location.StateCode | String | State, province or region code. |
| IPGeolocation.IP.Location.District | String | District or county name. |
| IPGeolocation.IP.Location.City | String | City name. |
| IPGeolocation.IP.Location.Locality | String | Neighborhood or suburb within the city. Requires include=geo_accuracy. |
| IPGeolocation.IP.Location.AccuracyRadius | String | Estimated accuracy radius in kilometers around the coordinates. Requires include=geo_accuracy. |
| IPGeolocation.IP.Location.Confidence | String | Confidence in the accuracy radius, one of low, medium or high. Requires include=geo_accuracy. |
| IPGeolocation.IP.Location.DMACode | String | Designated Market Area code. Populated for United States IP addresses only, and requires include=dma_code. |
| IPGeolocation.IP.Location.Zipcode | String | Postal or ZIP code. |
| IPGeolocation.IP.Location.Latitude | String | Latitude in decimal degrees. |
| IPGeolocation.IP.Location.Longitude | String | Longitude in decimal degrees. |
| IPGeolocation.IP.Location.IsEU | Boolean | Whether the country is a member of the European Union. |
| IPGeolocation.IP.Location.CountryFlag | String | URL of the country flag image. |
| IPGeolocation.IP.Location.GeonameID | String | GeoNames identifier of the place. |
| IPGeolocation.IP.Location.CountryEmoji | String | Unicode flag emoji of the country. |
| IPGeolocation.IP.CountryMetadata.CallingCode | String | International dialing prefix of the country. |
| IPGeolocation.IP.CountryMetadata.TLD | String | Country code top level domain. |
| IPGeolocation.IP.CountryMetadata.Languages | Unknown | Language codes commonly spoken in the country. |
| IPGeolocation.IP.Currency.Code | String | ISO 4217 currency code. |
| IPGeolocation.IP.Currency.Name | String | Currency name. |
| IPGeolocation.IP.Currency.Symbol | String | Currency symbol. |
| IPGeolocation.IP.Network.ConnectionType | String | Network access type, for example Cable or Mobile, when available. |
| IPGeolocation.IP.Network.Route | String | Network prefix in CIDR notation that contains the IP address. |
| IPGeolocation.IP.Network.IsAnycast | Boolean | Whether the IP address is announced from multiple locations as anycast. |
| IPGeolocation.IP.ASN.ASNumber | String | Autonomous System Number of the network, in AS<number> notation. |
| IPGeolocation.IP.ASN.Organization | String | Organization that operates the Autonomous System. |
| IPGeolocation.IP.ASN.Country | String | Country in which the Autonomous System is registered. |
| IPGeolocation.IP.ASN.Type | String | Autonomous System category, for example ISP, HOSTING, BUSINESS, EDUCATION or GOVERNMENT. |
| IPGeolocation.IP.ASN.Domain | String | Domain name of the Autonomous System operator. |
| IPGeolocation.IP.ASN.DateAllocated | String | Date on which the Autonomous System Number was allocated. |
| IPGeolocation.IP.ASN.RIR | String | Regional Internet Registry that allocated the Autonomous System Number. |
| IPGeolocation.IP.Company.Name | String | Company mapped to the IP address, often the ISP or network operator. |
| IPGeolocation.IP.Company.Type | String | Company category, for example ISP, HOSTING, BUSINESS, EDUCATION or GOVERNMENT. |
| IPGeolocation.IP.Company.Domain | String | Company domain name. |
| IPGeolocation.IP.TimeZone.Name | String | Time zone name in IANA format, for example Europe/Stockholm. |
| IPGeolocation.IP.TimeZone.Offset | Number | Standard UTC offset in hours. |
| IPGeolocation.IP.TimeZone.OffsetWithDST | Number | Effective UTC offset in hours, including daylight saving time when active. |
| IPGeolocation.IP.TimeZone.CurrentTime | String | Current local date and time at the IP location. |
| IPGeolocation.IP.TimeZone.CurrentTimeUnix | Number | Current local time as Unix epoch seconds. |
| IPGeolocation.IP.TimeZone.CurrentTZAbbreviation | String | Current time zone abbreviation, for example CET. |
| IPGeolocation.IP.TimeZone.CurrentTZFullName | String | Current time zone full name. |
| IPGeolocation.IP.TimeZone.StandardTZAbbreviation | String | Standard, non daylight saving, time zone abbreviation. |
| IPGeolocation.IP.TimeZone.StandardTZFullName | String | Standard, non daylight saving, time zone full name. |
| IPGeolocation.IP.TimeZone.IsDST | Boolean | Whether daylight saving time is currently active. |
| IPGeolocation.IP.TimeZone.DSTSavings | Number | Daylight saving time shift in hours. |
| IPGeolocation.IP.TimeZone.DSTExists | Boolean | Whether the time zone observes daylight saving time at any point in the year. |
| IPGeolocation.IP.TimeZone.DSTTZAbbreviation | String | Time zone abbreviation used while daylight saving time is active. |
| IPGeolocation.IP.TimeZone.DSTTZFullName | String | Time zone full name used while daylight saving time is active. |
| IPGeolocation.IP.TimeZone.DSTStart.UTCTime | String | Moment in UTC at which daylight saving time starts. |
| IPGeolocation.IP.TimeZone.DSTStart.Duration | String | Clock change applied when daylight saving time starts. |
| IPGeolocation.IP.TimeZone.DSTStart.Gap | Boolean | Whether local time jumps forward, leaving local times that do not exist. |
| IPGeolocation.IP.TimeZone.DSTStart.DateTimeAfter | String | Local date and time immediately after the transition. |
| IPGeolocation.IP.TimeZone.DSTStart.DateTimeBefore | String | Local date and time immediately before the transition. |
| IPGeolocation.IP.TimeZone.DSTStart.Overlap | Boolean | Whether local times repeat at the transition. |
| IPGeolocation.IP.TimeZone.DSTEnd.UTCTime | String | Moment in UTC at which daylight saving time ends. |
| IPGeolocation.IP.TimeZone.DSTEnd.Duration | String | Clock change applied when daylight saving time ends. |
| IPGeolocation.IP.TimeZone.DSTEnd.Gap | Boolean | Whether local time jumps forward at the transition. |
| IPGeolocation.IP.TimeZone.DSTEnd.DateTimeAfter | String | Local date and time immediately after the transition. |
| IPGeolocation.IP.TimeZone.DSTEnd.DateTimeBefore | String | Local date and time immediately before the transition. |
| IPGeolocation.IP.TimeZone.DSTEnd.Overlap | Boolean | Whether local times repeat at the transition. |
| IPGeolocation.IP.Security.ThreatScore | Number | Aggregate risk score from 0 to 100, where 100 is the highest risk. |
| IPGeolocation.IP.Security.IsTor | Boolean | Whether the IP address is a Tor exit node. |
| IPGeolocation.IP.Security.IsProxy | Boolean | Whether the IP address belongs to a proxy network. |
| IPGeolocation.IP.Security.ProxyProviderNames | Unknown | Names of the detected proxy providers. |
| IPGeolocation.IP.Security.ProxyConfidenceScore | Number | Confidence from 0 to 100 in the proxy detection. Defaults to 0 when not detected. |
| IPGeolocation.IP.Security.ProxyLastSeen | String | Date on which proxy activity was last observed, in YYYY-MM-DD format. |
| IPGeolocation.IP.Security.IsResidentialProxy | Boolean | Whether the IP address belongs to a residential proxy network. |
| IPGeolocation.IP.Security.IsVPN | Boolean | Whether the IP address belongs to a VPN network. |
| IPGeolocation.IP.Security.VPNProviderNames | Unknown | Names of the detected VPN providers. |
| IPGeolocation.IP.Security.VPNConfidenceScore | Number | Confidence from 0 to 100 in the VPN detection. Defaults to 0 when not detected. |
| IPGeolocation.IP.Security.VPNLastSeen | String | Date on which VPN activity was last observed, in YYYY-MM-DD format. |
| IPGeolocation.IP.Security.IsRelay | Boolean | Whether the IP address belongs to a privacy relay network. |
| IPGeolocation.IP.Security.RelayProviderName | String | Name of the detected relay provider. |
| IPGeolocation.IP.Security.IsAnonymous | Boolean | Whether any anonymizing route was detected, that is a VPN, proxy, Tor or relay. |
| IPGeolocation.IP.Security.IsKnownAttacker | Boolean | Whether the IP address is flagged for known attacker behavior. |
| IPGeolocation.IP.Security.IsBot | Boolean | Whether the IP address is associated with suspicious automated activity. |
| IPGeolocation.IP.Security.IsSpam | Boolean | Whether the IP address is associated with spam activity. |
| IPGeolocation.IP.Security.IsCloudProvider | Boolean | Whether the IP address belongs to a cloud or hosting provider range. |
| IPGeolocation.IP.Security.CloudProviderName | String | Name of the cloud or hosting provider. |
| IPGeolocation.IP.Abuse.Route | String | Abuse handling IP range in CIDR notation. |
| IPGeolocation.IP.Abuse.Country | String | ISO 3166-1 alpha-2 country code in which the abuse contact is registered. |
| IPGeolocation.IP.Abuse.Name | String | Name of the abuse contact role, team or person. |
| IPGeolocation.IP.Abuse.Organization | String | Organization that manages the IP address range. |
| IPGeolocation.IP.Abuse.Kind | String | Contact type reported by the registry, either group or individual. |
| IPGeolocation.IP.Abuse.Address | String | Registered postal address of the organization that owns the IP address. |
| IPGeolocation.IP.Abuse.Emails | Unknown | Email addresses for reporting abuse. |
| IPGeolocation.IP.Abuse.PhoneNumbers | Unknown | Phone numbers for reporting abuse. |
| IPGeolocation.IP.UserAgent.UserAgentString | String | Raw User-Agent string that was parsed. |
| IPGeolocation.IP.UserAgent.Name | String | Detected user agent product name. |
| IPGeolocation.IP.UserAgent.Type | String | User agent category, for example Browser, Robot or Hacker. |
| IPGeolocation.IP.UserAgent.Version | String | Full product version. |
| IPGeolocation.IP.UserAgent.VersionMajor | String | Major product version. |
| IPGeolocation.IP.UserAgent.Device.Name | String | Detected device label. |
| IPGeolocation.IP.UserAgent.Device.Type | String | Device category, for example Desktop, Mobile or Tablet. |
| IPGeolocation.IP.UserAgent.Device.Brand | String | Device vendor or brand. |
| IPGeolocation.IP.UserAgent.Device.CPU | String | Detected CPU or architecture. |
| IPGeolocation.IP.UserAgent.Engine.Name | String | Rendering engine name. |
| IPGeolocation.IP.UserAgent.Engine.Type | String | Rendering engine category. |
| IPGeolocation.IP.UserAgent.Engine.Version | String | Full rendering engine version. |
| IPGeolocation.IP.UserAgent.Engine.VersionMajor | String | Major rendering engine version. |
| IPGeolocation.IP.UserAgent.OperatingSystem.Name | String | Operating system name. |
| IPGeolocation.IP.UserAgent.OperatingSystem.Type | String | Operating system category. |
| IPGeolocation.IP.UserAgent.OperatingSystem.Version | String | Operating system version. |
| IPGeolocation.IP.UserAgent.OperatingSystem.VersionMajor | String | Major operating system version. |
| IPGeolocation.IP.UserAgent.OperatingSystem.Build | String | Operating system build identifier. |

#### Command Example

```
!ip ip=2.56.188.34
```

#### Human Readable Output

### IPGeolocation.io IP Geolocation for 2.56.188.34
|IP Address|Hostname|City|State / Province|Country|Country Code|Continent|Postal Code|Latitude|Longitude|Time Zone|Local Time|ASN|AS Organization|AS Type|Company|Route|Anycast|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2.56.188.34 | 2.56.188.34 | Dallas | Texas | United States | US | North America | 75201 | 32.77822 | -96.79512 | America/Chicago | 2026-03-07 03:37:38.996-0600 | AS62240 | Clouvider Limited | HOSTING | Packethub S.A. | 2.56.188.0/22 | no |

### IPGeolocation.io IP Security for 2.56.188.34
|IP Address|Threat Score|Anonymous|Known Attacker|Tor Exit Node|VPN|VPN Providers|VPN Confidence|VPN Last Seen|Proxy|Proxy Providers|Proxy Confidence|Proxy Last Seen|Residential Proxy|Relay|Bot|Spam|Cloud Provider|Cloud Provider Name|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2.56.188.34 | 80 | yes | yes | no | yes | Nord VPN | 80 | 2026-01-19 | yes | Zyte Proxy | 80 | 2025-12-12 | yes | no | no | no | yes | Packethub S.A. |

**Reputation:** Assessed as malicious because threat score 80 is at or above the malicious threshold 70; the IP address is flagged as a known attacker.

#### Context Example

```json
{
  "DBotScore": {
    "Indicator": "2.56.188.34",
    "Type": "ip",
    "Vendor": "IPGeolocation.io",
    "Score": 3,
    "Reliability": "B - Usually reliable"
  },
  "IP": {
    "Address": "2.56.188.34",
    "ASN": "AS62240",
    "ASOwner": "Clouvider Limited",
    "Region": "Texas",
    "Hostname": "2.56.188.34",
    "Geo": {
      "Location": "32.77822:-96.79512",
      "Country": "US",
      "Description": "Dallas, Texas, United States"
    },
    "Organization": {
      "Name": "Packethub S.A.",
      "Type": "BUSINESS"
    },
    "Tags": [
      "vpn",
      "proxy",
      "residential-proxy",
      "known-attacker",
      "cloud-provider"
    ],
    "Malicious": {
      "Vendor": "IPGeolocation.io",
      "Description": "Assessed as malicious because threat score 80 is at or above the malicious threshold 70; the IP address is flagged as a known attacker."
    }
  },
  "IPGeolocation": {
    "IP": {
      "IP": "2.56.188.34",
      "Hostname": "2.56.188.34",
      "Location": {
        "ContinentCode": "NA",
        "ContinentName": "North America",
        "CountryCode2": "US",
        "CountryCode3": "USA",
        "CountryName": "United States",
        "CountryNameOfficial": "United States of America",
        "CountryCapital": "Washington, D.C.",
        "StateProv": "Texas",
        "StateCode": "US-TX",
        "District": "Dallas",
        "City": "Dallas",
        "Zipcode": "75201",
        "Latitude": "32.77822",
        "Longitude": "-96.79512",
        "IsEU": false,
        "CountryFlag": "https://ipgeolocation.io/static/flags/us_64.png",
        "GeonameID": "4684902",
        "CountryEmoji": "🇺🇸"
      },
      "CountryMetadata": {
        "CallingCode": "+1",
        "TLD": ".us",
        "Languages": [
          "en-US",
          "es-US",
          "haw",
          "fr"
        ]
      },
      "Currency": {
        "Code": "USD",
        "Name": "US Dollar",
        "Symbol": "$"
      },
      "Network": {
        "Route": "2.56.188.0/22",
        "IsAnycast": false
      },
      "ASN": {
        "ASNumber": "AS62240",
        "Organization": "Clouvider Limited",
        "Country": "GB",
        "Type": "HOSTING",
        "Domain": "clouvider.net",
        "DateAllocated": "2013-12-12",
        "RIR": "RIPE"
      },
      "Company": {
        "Name": "Packethub S.A.",
        "Type": "BUSINESS",
        "Domain": "packethub.com"
      },
      "TimeZone": {
        "Name": "America/Chicago",
        "Offset": -6,
        "OffsetWithDST": -6,
        "CurrentTime": "2026-03-07 03:37:38.996-0600",
        "CurrentTimeUnix": 1772876258.996,
        "CurrentTZAbbreviation": "CST",
        "CurrentTZFullName": "Central Standard Time",
        "StandardTZAbbreviation": "CST",
        "StandardTZFullName": "Central Standard Time",
        "IsDST": false,
        "DSTSavings": 0,
        "DSTExists": true,
        "DSTTZAbbreviation": "CDT",
        "DSTTZFullName": "Central Daylight Time",
        "DSTStart": {
          "UTCTime": "2026-03-08 TIME 08:00",
          "Duration": "+1.00H",
          "Gap": true,
          "DateTimeAfter": "2026-03-08 TIME 03:00",
          "DateTimeBefore": "2026-03-08 TIME 02:00",
          "Overlap": false
        },
        "DSTEnd": {
          "UTCTime": "2026-11-01 TIME 07:00",
          "Duration": "-1.00H",
          "Gap": false,
          "DateTimeAfter": "2026-11-01 TIME 01:00",
          "DateTimeBefore": "2026-11-01 TIME 02:00",
          "Overlap": true
        }
      },
      "Security": {
        "ThreatScore": 80,
        "IsTor": false,
        "IsProxy": true,
        "ProxyProviderNames": [
          "Zyte Proxy"
        ],
        "ProxyConfidenceScore": 80,
        "ProxyLastSeen": "2025-12-12",
        "IsResidentialProxy": true,
        "IsVPN": true,
        "VPNProviderNames": [
          "Nord VPN"
        ],
        "VPNConfidenceScore": 80,
        "VPNLastSeen": "2026-01-19",
        "IsRelay": false,
        "IsAnonymous": true,
        "IsKnownAttacker": true,
        "IsBot": false,
        "IsSpam": false,
        "IsCloudProvider": true,
        "CloudProviderName": "Packethub S.A."
      }
    }
  }
}
```

### ipgeolocation-ip-lookup

Performs a full IP intelligence lookup against the unified IP Geolocation API
endpoint. By default the response carries location, country metadata, currency, network, ASN, company and time zone
data. The `include` argument adds the optional modules that IPGeolocation.io exposes on the same endpoint, namely
geolocation accuracy, DMA code, parsed user agent, IP security, abuse contact and reverse DNS hostname.

This command does not set a reputation. Use `!ip` when a DBotScore is required.

#### Base Command

`ipgeolocation-ip-lookup`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Comma separated list of IPv4 addresses, IPv6 addresses or domain names to look up. Domain lookups require a paid subscription. Accepts a comma separated list. | Required |
| include | Comma separated list of optional modules to add to the response. Each module has its own credit cost, security adds 2 credits and abuse adds 1 credit on top of the base lookup. All modules require a paid subscription. When more than one hostname option is supplied the API applies the precedence liveHostname, hostname, hostnameFallbackLive. Possible values are: geo_accuracy, dma_code, user_agent, security, abuse, hostname, liveHostname, hostnameFallbackLive, *. Accepts a comma separated list. | Optional |
| lang | Language of the response. Only English is available on the Free plan. Possible values are: en, de, ru, ja, fr, cn, es, cs, it, ko, fa, pt, ar. | Optional |
| fields | Comma separated list of response fields to return, using the documented dot notation, for example location.city. Reduces the response size without changing the credit cost. Accepts a comma separated list. | Optional |
| excludes | Comma separated list of response fields or objects to omit, using the documented dot notation, for example currency or location.continent_code. The ip field is always returned. Accepts a comma separated list. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IPGeolocation.IP.IP | String | The IP address that was looked up. |
| IPGeolocation.IP.Domain | String | The domain name submitted, returned only for domain based lookups. |
| IPGeolocation.IP.Hostname | String | Reverse DNS hostname of the IP address. The API echoes the IP address when no hostname resolves. |
| IPGeolocation.IP.Location.ContinentCode | String | Two letter continent code, for example EU. |
| IPGeolocation.IP.Location.ContinentName | String | Continent name, for example Europe. |
| IPGeolocation.IP.Location.CountryCode2 | String | ISO 3166-1 alpha-2 country code, for example SE. |
| IPGeolocation.IP.Location.CountryCode3 | String | ISO 3166-1 alpha-3 country code, for example SWE. |
| IPGeolocation.IP.Location.CountryName | String | Common country name. |
| IPGeolocation.IP.Location.CountryNameOfficial | String | Official country name, when it differs from the common name. |
| IPGeolocation.IP.Location.CountryCapital | String | Capital city of the country. |
| IPGeolocation.IP.Location.StateProv | String | State, province or region name. |
| IPGeolocation.IP.Location.StateCode | String | State, province or region code. |
| IPGeolocation.IP.Location.District | String | District or county name. |
| IPGeolocation.IP.Location.City | String | City name. |
| IPGeolocation.IP.Location.Locality | String | Neighborhood or suburb within the city. Requires include=geo_accuracy. |
| IPGeolocation.IP.Location.AccuracyRadius | String | Estimated accuracy radius in kilometers around the coordinates. Requires include=geo_accuracy. |
| IPGeolocation.IP.Location.Confidence | String | Confidence in the accuracy radius, one of low, medium or high. Requires include=geo_accuracy. |
| IPGeolocation.IP.Location.DMACode | String | Designated Market Area code. Populated for United States IP addresses only, and requires include=dma_code. |
| IPGeolocation.IP.Location.Zipcode | String | Postal or ZIP code. |
| IPGeolocation.IP.Location.Latitude | String | Latitude in decimal degrees. |
| IPGeolocation.IP.Location.Longitude | String | Longitude in decimal degrees. |
| IPGeolocation.IP.Location.IsEU | Boolean | Whether the country is a member of the European Union. |
| IPGeolocation.IP.Location.CountryFlag | String | URL of the country flag image. |
| IPGeolocation.IP.Location.GeonameID | String | GeoNames identifier of the place. |
| IPGeolocation.IP.Location.CountryEmoji | String | Unicode flag emoji of the country. |
| IPGeolocation.IP.CountryMetadata.CallingCode | String | International dialing prefix of the country. |
| IPGeolocation.IP.CountryMetadata.TLD | String | Country code top level domain. |
| IPGeolocation.IP.CountryMetadata.Languages | Unknown | Language codes commonly spoken in the country. |
| IPGeolocation.IP.Currency.Code | String | ISO 4217 currency code. |
| IPGeolocation.IP.Currency.Name | String | Currency name. |
| IPGeolocation.IP.Currency.Symbol | String | Currency symbol. |
| IPGeolocation.IP.Network.ConnectionType | String | Network access type, for example Cable or Mobile, when available. |
| IPGeolocation.IP.Network.Route | String | Network prefix in CIDR notation that contains the IP address. |
| IPGeolocation.IP.Network.IsAnycast | Boolean | Whether the IP address is announced from multiple locations as anycast. |
| IPGeolocation.IP.ASN.ASNumber | String | Autonomous System Number of the network, in AS<number> notation. |
| IPGeolocation.IP.ASN.Organization | String | Organization that operates the Autonomous System. |
| IPGeolocation.IP.ASN.Country | String | Country in which the Autonomous System is registered. |
| IPGeolocation.IP.ASN.Type | String | Autonomous System category, for example ISP, HOSTING, BUSINESS, EDUCATION or GOVERNMENT. |
| IPGeolocation.IP.ASN.Domain | String | Domain name of the Autonomous System operator. |
| IPGeolocation.IP.ASN.DateAllocated | String | Date on which the Autonomous System Number was allocated. |
| IPGeolocation.IP.ASN.RIR | String | Regional Internet Registry that allocated the Autonomous System Number. |
| IPGeolocation.IP.Company.Name | String | Company mapped to the IP address, often the ISP or network operator. |
| IPGeolocation.IP.Company.Type | String | Company category, for example ISP, HOSTING, BUSINESS, EDUCATION or GOVERNMENT. |
| IPGeolocation.IP.Company.Domain | String | Company domain name. |
| IPGeolocation.IP.TimeZone.Name | String | Time zone name in IANA format, for example Europe/Stockholm. |
| IPGeolocation.IP.TimeZone.Offset | Number | Standard UTC offset in hours. |
| IPGeolocation.IP.TimeZone.OffsetWithDST | Number | Effective UTC offset in hours, including daylight saving time when active. |
| IPGeolocation.IP.TimeZone.CurrentTime | String | Current local date and time at the IP location. |
| IPGeolocation.IP.TimeZone.CurrentTimeUnix | Number | Current local time as Unix epoch seconds. |
| IPGeolocation.IP.TimeZone.CurrentTZAbbreviation | String | Current time zone abbreviation, for example CET. |
| IPGeolocation.IP.TimeZone.CurrentTZFullName | String | Current time zone full name. |
| IPGeolocation.IP.TimeZone.StandardTZAbbreviation | String | Standard, non daylight saving, time zone abbreviation. |
| IPGeolocation.IP.TimeZone.StandardTZFullName | String | Standard, non daylight saving, time zone full name. |
| IPGeolocation.IP.TimeZone.IsDST | Boolean | Whether daylight saving time is currently active. |
| IPGeolocation.IP.TimeZone.DSTSavings | Number | Daylight saving time shift in hours. |
| IPGeolocation.IP.TimeZone.DSTExists | Boolean | Whether the time zone observes daylight saving time at any point in the year. |
| IPGeolocation.IP.TimeZone.DSTTZAbbreviation | String | Time zone abbreviation used while daylight saving time is active. |
| IPGeolocation.IP.TimeZone.DSTTZFullName | String | Time zone full name used while daylight saving time is active. |
| IPGeolocation.IP.TimeZone.DSTStart.UTCTime | String | Moment in UTC at which daylight saving time starts. |
| IPGeolocation.IP.TimeZone.DSTStart.Duration | String | Clock change applied when daylight saving time starts. |
| IPGeolocation.IP.TimeZone.DSTStart.Gap | Boolean | Whether local time jumps forward, leaving local times that do not exist. |
| IPGeolocation.IP.TimeZone.DSTStart.DateTimeAfter | String | Local date and time immediately after the transition. |
| IPGeolocation.IP.TimeZone.DSTStart.DateTimeBefore | String | Local date and time immediately before the transition. |
| IPGeolocation.IP.TimeZone.DSTStart.Overlap | Boolean | Whether local times repeat at the transition. |
| IPGeolocation.IP.TimeZone.DSTEnd.UTCTime | String | Moment in UTC at which daylight saving time ends. |
| IPGeolocation.IP.TimeZone.DSTEnd.Duration | String | Clock change applied when daylight saving time ends. |
| IPGeolocation.IP.TimeZone.DSTEnd.Gap | Boolean | Whether local time jumps forward at the transition. |
| IPGeolocation.IP.TimeZone.DSTEnd.DateTimeAfter | String | Local date and time immediately after the transition. |
| IPGeolocation.IP.TimeZone.DSTEnd.DateTimeBefore | String | Local date and time immediately before the transition. |
| IPGeolocation.IP.TimeZone.DSTEnd.Overlap | Boolean | Whether local times repeat at the transition. |
| IPGeolocation.IP.Security.ThreatScore | Number | Aggregate risk score from 0 to 100, where 100 is the highest risk. |
| IPGeolocation.IP.Security.IsTor | Boolean | Whether the IP address is a Tor exit node. |
| IPGeolocation.IP.Security.IsProxy | Boolean | Whether the IP address belongs to a proxy network. |
| IPGeolocation.IP.Security.ProxyProviderNames | Unknown | Names of the detected proxy providers. |
| IPGeolocation.IP.Security.ProxyConfidenceScore | Number | Confidence from 0 to 100 in the proxy detection. Defaults to 0 when not detected. |
| IPGeolocation.IP.Security.ProxyLastSeen | String | Date on which proxy activity was last observed, in YYYY-MM-DD format. |
| IPGeolocation.IP.Security.IsResidentialProxy | Boolean | Whether the IP address belongs to a residential proxy network. |
| IPGeolocation.IP.Security.IsVPN | Boolean | Whether the IP address belongs to a VPN network. |
| IPGeolocation.IP.Security.VPNProviderNames | Unknown | Names of the detected VPN providers. |
| IPGeolocation.IP.Security.VPNConfidenceScore | Number | Confidence from 0 to 100 in the VPN detection. Defaults to 0 when not detected. |
| IPGeolocation.IP.Security.VPNLastSeen | String | Date on which VPN activity was last observed, in YYYY-MM-DD format. |
| IPGeolocation.IP.Security.IsRelay | Boolean | Whether the IP address belongs to a privacy relay network. |
| IPGeolocation.IP.Security.RelayProviderName | String | Name of the detected relay provider. |
| IPGeolocation.IP.Security.IsAnonymous | Boolean | Whether any anonymizing route was detected, that is a VPN, proxy, Tor or relay. |
| IPGeolocation.IP.Security.IsKnownAttacker | Boolean | Whether the IP address is flagged for known attacker behavior. |
| IPGeolocation.IP.Security.IsBot | Boolean | Whether the IP address is associated with suspicious automated activity. |
| IPGeolocation.IP.Security.IsSpam | Boolean | Whether the IP address is associated with spam activity. |
| IPGeolocation.IP.Security.IsCloudProvider | Boolean | Whether the IP address belongs to a cloud or hosting provider range. |
| IPGeolocation.IP.Security.CloudProviderName | String | Name of the cloud or hosting provider. |
| IPGeolocation.IP.Abuse.Route | String | Abuse handling IP range in CIDR notation. |
| IPGeolocation.IP.Abuse.Country | String | ISO 3166-1 alpha-2 country code in which the abuse contact is registered. |
| IPGeolocation.IP.Abuse.Name | String | Name of the abuse contact role, team or person. |
| IPGeolocation.IP.Abuse.Organization | String | Organization that manages the IP address range. |
| IPGeolocation.IP.Abuse.Kind | String | Contact type reported by the registry, either group or individual. |
| IPGeolocation.IP.Abuse.Address | String | Registered postal address of the organization that owns the IP address. |
| IPGeolocation.IP.Abuse.Emails | Unknown | Email addresses for reporting abuse. |
| IPGeolocation.IP.Abuse.PhoneNumbers | Unknown | Phone numbers for reporting abuse. |
| IPGeolocation.IP.UserAgent.UserAgentString | String | Raw User-Agent string that was parsed. |
| IPGeolocation.IP.UserAgent.Name | String | Detected user agent product name. |
| IPGeolocation.IP.UserAgent.Type | String | User agent category, for example Browser, Robot or Hacker. |
| IPGeolocation.IP.UserAgent.Version | String | Full product version. |
| IPGeolocation.IP.UserAgent.VersionMajor | String | Major product version. |
| IPGeolocation.IP.UserAgent.Device.Name | String | Detected device label. |
| IPGeolocation.IP.UserAgent.Device.Type | String | Device category, for example Desktop, Mobile or Tablet. |
| IPGeolocation.IP.UserAgent.Device.Brand | String | Device vendor or brand. |
| IPGeolocation.IP.UserAgent.Device.CPU | String | Detected CPU or architecture. |
| IPGeolocation.IP.UserAgent.Engine.Name | String | Rendering engine name. |
| IPGeolocation.IP.UserAgent.Engine.Type | String | Rendering engine category. |
| IPGeolocation.IP.UserAgent.Engine.Version | String | Full rendering engine version. |
| IPGeolocation.IP.UserAgent.Engine.VersionMajor | String | Major rendering engine version. |
| IPGeolocation.IP.UserAgent.OperatingSystem.Name | String | Operating system name. |
| IPGeolocation.IP.UserAgent.OperatingSystem.Type | String | Operating system category. |
| IPGeolocation.IP.UserAgent.OperatingSystem.Version | String | Operating system version. |
| IPGeolocation.IP.UserAgent.OperatingSystem.VersionMajor | String | Major operating system version. |
| IPGeolocation.IP.UserAgent.OperatingSystem.Build | String | Operating system build identifier. |

#### Command Example

```
!ipgeolocation-ip-lookup ip=8.8.8.8
```

#### Human Readable Output

### IPGeolocation.io IP Geolocation for 8.8.8.8
|IP Address|City|State / Province|Country|Country Code|Continent|Postal Code|Latitude|Longitude|Time Zone|Local Time|ASN|AS Organization|
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 8.8.8.8 | Mountain View | California | United States | US | North America | 94043 | 37.42240 | -122.08421 | America/Los_Angeles | 2026-03-07 01:37:39.506-0800 | AS15169 | Google LLC |

#### Context Example

```json
{
  "IPGeolocation": {
    "IP": {
      "IP": "8.8.8.8",
      "Location": {
        "ContinentCode": "NA",
        "ContinentName": "North America",
        "CountryCode2": "US",
        "CountryCode3": "USA",
        "CountryName": "United States",
        "CountryNameOfficial": "United States of America",
        "CountryCapital": "Washington, D.C.",
        "StateProv": "California",
        "StateCode": "US-CA",
        "District": "Santa Clara",
        "City": "Mountain View",
        "Zipcode": "94043",
        "Latitude": "37.42240",
        "Longitude": "-122.08421",
        "IsEU": false,
        "CountryFlag": "https://ipgeolocation.io/static/flags/us_64.png",
        "GeonameID": "5375481",
        "CountryEmoji": "🇺🇸"
      },
      "CountryMetadata": {
        "CallingCode": "+1",
        "TLD": ".us",
        "Languages": [
          "en-US",
          "es-US",
          "haw",
          "fr"
        ]
      },
      "Currency": {
        "Code": "USD",
        "Name": "US Dollar",
        "Symbol": "$"
      },
      "ASN": {
        "ASNumber": "AS15169",
        "Organization": "Google LLC",
        "Country": "US"
      },
      "TimeZone": {
        "Name": "America/Los_Angeles",
        "Offset": -8,
        "OffsetWithDST": -8,
        "CurrentTime": "2026-03-07 01:37:39.506-0800",
        "CurrentTimeUnix": 1772876259.506,
        "CurrentTZAbbreviation": "PST",
        "CurrentTZFullName": "Pacific Standard Time",
        "StandardTZAbbreviation": "PST",
        "StandardTZFullName": "Pacific Standard Time",
        "IsDST": false,
        "DSTSavings": 0,
        "DSTExists": true,
        "DSTTZAbbreviation": "PDT",
        "DSTTZFullName": "Pacific Daylight Time"
      }
    }
  }
}
```

### ipgeolocation-ip-security

Returns the dedicated IP Security API result for one or more IP addresses. Use it
for VPN and proxy detection, Tor exit node identification, residential proxy detection, relay detection, bot and spam
signals, known attacker signals and cloud hosting context, without paying for the geolocation payload.

Each lookup consumes 2 credits. This command does not set a reputation, so it is safe to use inside detection logic
that must not influence indicator verdicts.

#### Base Command

`ipgeolocation-ip-security`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Comma separated list of IPv4 or IPv6 addresses. Domain names are not supported by this endpoint. Accepts a comma separated list. | Required |
| fields | Comma separated list of response fields to return, using the documented dot notation, for example location.city. Reduces the response size without changing the credit cost. Accepts a comma separated list. | Optional |
| excludes | Comma separated list of response fields or objects to omit, using the documented dot notation, for example currency or location.continent_code. The ip field is always returned. Accepts a comma separated list. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IPGeolocation.IP.IP | String | The IP address that was looked up. |
| IPGeolocation.IP.Security.ThreatScore | Number | Aggregate risk score from 0 to 100, where 100 is the highest risk. |
| IPGeolocation.IP.Security.IsTor | Boolean | Whether the IP address is a Tor exit node. |
| IPGeolocation.IP.Security.IsProxy | Boolean | Whether the IP address belongs to a proxy network. |
| IPGeolocation.IP.Security.ProxyProviderNames | Unknown | Names of the detected proxy providers. |
| IPGeolocation.IP.Security.ProxyConfidenceScore | Number | Confidence from 0 to 100 in the proxy detection. Defaults to 0 when not detected. |
| IPGeolocation.IP.Security.ProxyLastSeen | String | Date on which proxy activity was last observed, in YYYY-MM-DD format. |
| IPGeolocation.IP.Security.IsResidentialProxy | Boolean | Whether the IP address belongs to a residential proxy network. |
| IPGeolocation.IP.Security.IsVPN | Boolean | Whether the IP address belongs to a VPN network. |
| IPGeolocation.IP.Security.VPNProviderNames | Unknown | Names of the detected VPN providers. |
| IPGeolocation.IP.Security.VPNConfidenceScore | Number | Confidence from 0 to 100 in the VPN detection. Defaults to 0 when not detected. |
| IPGeolocation.IP.Security.VPNLastSeen | String | Date on which VPN activity was last observed, in YYYY-MM-DD format. |
| IPGeolocation.IP.Security.IsRelay | Boolean | Whether the IP address belongs to a privacy relay network. |
| IPGeolocation.IP.Security.RelayProviderName | String | Name of the detected relay provider. |
| IPGeolocation.IP.Security.IsAnonymous | Boolean | Whether any anonymizing route was detected, that is a VPN, proxy, Tor or relay. |
| IPGeolocation.IP.Security.IsKnownAttacker | Boolean | Whether the IP address is flagged for known attacker behavior. |
| IPGeolocation.IP.Security.IsBot | Boolean | Whether the IP address is associated with suspicious automated activity. |
| IPGeolocation.IP.Security.IsSpam | Boolean | Whether the IP address is associated with spam activity. |
| IPGeolocation.IP.Security.IsCloudProvider | Boolean | Whether the IP address belongs to a cloud or hosting provider range. |
| IPGeolocation.IP.Security.CloudProviderName | String | Name of the cloud or hosting provider. |

#### Command Example

```
!ipgeolocation-ip-security ip=2.56.188.34
```

#### Human Readable Output

### IPGeolocation.io IP Security for 2.56.188.34
|IP Address|Threat Score|Anonymous|Known Attacker|Tor Exit Node|VPN|VPN Providers|VPN Confidence|VPN Last Seen|Proxy|Proxy Providers|Proxy Confidence|Proxy Last Seen|Residential Proxy|Relay|Bot|Spam|Cloud Provider|Cloud Provider Name|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2.56.188.34 | 80 | yes | yes | no | yes | Nord VPN | 80 | 2026-01-19 | yes | Zyte Proxy | 80 | 2025-12-12 | yes | no | no | no | yes | Packethub S.A. |

#### Context Example

```json
{
  "IPGeolocation": {
    "IP": {
      "IP": "2.56.188.34",
      "Security": {
        "ThreatScore": 80,
        "IsTor": false,
        "IsProxy": true,
        "ProxyProviderNames": [
          "Zyte Proxy"
        ],
        "ProxyConfidenceScore": 80,
        "ProxyLastSeen": "2025-12-12",
        "IsResidentialProxy": true,
        "IsVPN": true,
        "VPNProviderNames": [
          "Nord VPN"
        ],
        "VPNConfidenceScore": 80,
        "VPNLastSeen": "2026-01-19",
        "IsRelay": false,
        "IsAnonymous": true,
        "IsKnownAttacker": true,
        "IsBot": false,
        "IsSpam": false,
        "IsCloudProvider": true,
        "CloudProviderName": "Packethub S.A."
      }
    }
  }
}
```

### ipgeolocation-abuse-contact

Returns the abuse contact registered against the network that owns an IP
address. Alongside the branded context the command populates the standard `IP.Registrar.Abuse` fields, so a takedown
or abuse notification playbook can read the contact details from the indicator without knowing which vendor supplied
them.

Each lookup consumes 1 credit.

#### Base Command

`ipgeolocation-abuse-contact`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | Comma separated list of IPv4 or IPv6 addresses. Accepts a comma separated list. | Required |
| fields | Comma separated list of response fields to return, using the documented dot notation, for example location.city. Reduces the response size without changing the credit cost. Accepts a comma separated list. | Optional |
| excludes | Comma separated list of response fields or objects to omit, using the documented dot notation, for example currency or location.continent_code. The ip field is always returned. Accepts a comma separated list. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IP.Address | String | The IP address. |
| IP.Registrar.Abuse.Name | String | The name of the abuse contact. |
| IP.Registrar.Abuse.Address | String | The postal address of the abuse contact. |
| IP.Registrar.Abuse.Country | String | The country of the abuse contact. |
| IP.Registrar.Abuse.Network | String | The network range handled by the abuse contact. |
| IP.Registrar.Abuse.Email | String | The email addresses of the abuse contact. |
| IP.Registrar.Abuse.Phone | String | The phone numbers of the abuse contact. |
| IPGeolocation.IP.IP | String | The IP address that was looked up. |
| IPGeolocation.IP.Abuse.Route | String | Abuse handling IP range in CIDR notation. |
| IPGeolocation.IP.Abuse.Country | String | ISO 3166-1 alpha-2 country code in which the abuse contact is registered. |
| IPGeolocation.IP.Abuse.Name | String | Name of the abuse contact role, team or person. |
| IPGeolocation.IP.Abuse.Organization | String | Organization that manages the IP address range. |
| IPGeolocation.IP.Abuse.Kind | String | Contact type reported by the registry, either group or individual. |
| IPGeolocation.IP.Abuse.Address | String | Registered postal address of the organization that owns the IP address. |
| IPGeolocation.IP.Abuse.Emails | Unknown | Email addresses for reporting abuse. |
| IPGeolocation.IP.Abuse.PhoneNumbers | Unknown | Phone numbers for reporting abuse. |

#### Command Example

```
!ipgeolocation-abuse-contact ip=1.0.0.0
```

#### Human Readable Output

### IPGeolocation.io Abuse Contact for 1.0.0.0
|IP Address|Abuse Contact Name|Contact Type|Emails|Phone Numbers|Route|Country|Registered Address|
|---|---|---|---|---|---|---|---|
| 1.0.0.0 | IRT-APNICRANDNET-AU | group | helpdesk@apnic.net | +61 7 3858 3100 | 1.0.0.0/24 | AU | PO Box 3646, South Brisbane, QLD 4101, Australia |

#### Context Example

```json
{
  "IP": {
    "Address": "1.0.0.0",
    "Registrar": {
      "Abuse": {
        "Name": "IRT-APNICRANDNET-AU",
        "Address": "PO Box 3646\nSouth Brisbane, QLD 4101\nAustralia",
        "Country": "AU",
        "Network": "1.0.0.0/24",
        "Phone": "+61 7 3858 3100",
        "Email": "helpdesk@apnic.net"
      }
    }
  },
  "IPGeolocation": {
    "IP": {
      "IP": "1.0.0.0",
      "Abuse": {
        "Route": "1.0.0.0/24",
        "Country": "AU",
        "Name": "IRT-APNICRANDNET-AU",
        "Kind": "group",
        "Address": "PO Box 3646\nSouth Brisbane, QLD 4101\nAustralia",
        "Emails": [
          "helpdesk@apnic.net"
        ],
        "PhoneNumbers": [
          "+61 7 3858 3100"
        ]
      }
    }
  }
}
```

### ipgeolocation-asn

Returns Autonomous System details, looked up either by ASN or by IP address. In addition
to the organization, category, registry and allocation data, the `include` argument returns the announced prefixes,
the peering relationships, the upstream and downstream Autonomous Systems and the raw WHOIS record.

Each lookup consumes 1 credit.

#### Base Command

`ipgeolocation-asn`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asn | Comma separated list of Autonomous System Numbers to look up. Both 24940 and AS24940 are accepted. Mutually exclusive with the ip argument. Accepts a comma separated list. | Optional |
| ip | Comma separated list of IPv4 or IPv6 addresses to resolve to their Autonomous System. Mutually exclusive with the asn argument. Accepts a comma separated list. | Optional |
| include | Comma separated list of additional routing objects to add to the response. Possible values are: peers, downstreams, upstreams, routes, whois_response. Accepts a comma separated list. | Optional |
| fields | Comma separated list of response fields to return, using the documented dot notation, for example location.city. Reduces the response size without changing the credit cost. Accepts a comma separated list. | Optional |
| excludes | Comma separated list of response fields or objects to omit, using the documented dot notation, for example currency or location.continent_code. The ip field is always returned. Accepts a comma separated list. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IPGeolocation.ASN.IP | String | The IP address that was looked up. |
| IPGeolocation.ASN.ASNumber | String | Autonomous System Number of the network, in AS<number> notation. |
| IPGeolocation.ASN.Organization | String | Organization that operates the Autonomous System. |
| IPGeolocation.ASN.Country | String | Country in which the Autonomous System is registered. |
| IPGeolocation.ASN.Type | String | Autonomous System category, for example ISP, HOSTING, BUSINESS, EDUCATION or GOVERNMENT. |
| IPGeolocation.ASN.Domain | String | The domain name submitted, returned only for domain based lookups. |
| IPGeolocation.ASN.DateAllocated | String | Date on which the Autonomous System Number was allocated. |
| IPGeolocation.ASN.RIR | String | Regional Internet Registry that allocated the Autonomous System Number. |
| IPGeolocation.ASN.ASNName | String | Official Autonomous System handle. |
| IPGeolocation.ASN.AllocationStatus | String | Current allocation status of the Autonomous System Number. |
| IPGeolocation.ASN.NumOfIPv4Routes | String | Number of distinct IPv4 prefixes announced by the Autonomous System. |
| IPGeolocation.ASN.NumOfIPv6Routes | String | Number of distinct IPv6 prefixes announced by the Autonomous System. |
| IPGeolocation.ASN.Routes | Unknown | IPv4 and IPv6 prefixes announced by the Autonomous System. |
| IPGeolocation.ASN.Peers | Unknown | Autonomous Systems that peer directly with this one. |
| IPGeolocation.ASN.Upstreams | Unknown | Upstream provider Autonomous Systems. |
| IPGeolocation.ASN.Downstreams | Unknown | Downstream customer Autonomous Systems. |
| IPGeolocation.ASN.WhoisResponse | String | Raw WHOIS record text for the Autonomous System. |

#### Command Example

```
!ipgeolocation-asn asn=AS24940
```

#### Human Readable Output

### IPGeolocation.io ASN Details for AS24940
|ASN|AS Name|Organization|Type|Domain|Country|RIR|Date Allocated|Allocation Status|IPv4 Routes|IPv6 Routes|
|---|---|---|---|---|---|---|---|---|---|---|
| AS24940 | HETZNER-AS | Hetzner Online GmbH | HOSTING | hetzner.com | DE | RIPE | 2002-06-03 | ASSIGNED | 84 | 6 |

#### Context Example

```json
{
  "IPGeolocation": {
    "ASN": {
      "ASNumber": "AS24940",
      "Organization": "Hetzner Online GmbH",
      "Country": "DE",
      "Type": "HOSTING",
      "Domain": "hetzner.com",
      "DateAllocated": "2002-06-03",
      "RIR": "RIPE",
      "ASNName": "HETZNER-AS",
      "AllocationStatus": "ASSIGNED",
      "NumOfIPv4Routes": "84",
      "NumOfIPv6Routes": "6"
    }
  }
}
```

## Best Practices

- **Scope the module you pay for.** The unified `/v3/ipgeo` endpoint is convenient, but each optional module adds
  credits. Reach for `ipgeolocation-ip-security` when a playbook branch only needs a threat verdict.
- **Tune the thresholds to your environment before you trust the verdict.** The defaults (70 for Malicious, 40 for
  Suspicious) are a starting point. Review a sample of real traffic and adjust.
- **Reconsider the anonymizer rule for internal use cases.** If your workforce connects over a corporate VPN, a
  detected VPN is not by itself suspicious. Clear **Treat anonymizing networks as Suspicious** for those instances,
  or create a second instance with different settings for a different playbook.
- **Read the flags, not only the score.** IPGeolocation.io returns `is_residential_proxy`, `is_cloud_provider` and
  provider names alongside the score. A residential proxy on a consumer ISP and a scanner in a cloud range deserve
  different handling even at the same threat score.
- **Treat confidence and recency as first class.** `proxy_confidence_score`, `vpn_confidence_score`,
  `proxy_last_seen` and `vpn_last_seen` tell you how strong and how fresh a detection is. A VPN last seen months ago
  is weaker evidence than one seen yesterday.
- **Use the accuracy radius before acting on a city.** Request `include=geo_accuracy` and read
  `Location.AccuracyRadius` and `Location.Confidence`. IP geolocation is reliable at country level and progressively
  less precise at city level, so do not build an impossible travel rule on a city alone.
- **Do not block on geolocation alone.** Combine the security flags with your own telemetry. IP addresses are
  reassigned, and shared ranges such as carrier grade NAT put many users behind one address.
- **Cache aggressively.** Indicator caching in Cortex XSOAR avoids repeat spend, and IPGeolocation.io refreshes
  geolocation data every 24 hours and security data at least twice per 24 hours, so sub hourly re-enrichment rarely
  adds value.
- **Keep the API key in the credentials store.** Configure the key through the Cortex XSOAR credentials manager
  rather than typing it into each instance.

## Example Playbook

The pack ships a playbook named **IPGeolocation.io - IP Enrichment** that demonstrates a typical enrichment path.

1. The playbook takes an `IP` input, which defaults to the IP indicators found in the incident context.
2. It calls `!ip` to obtain a reputation and populate the standard `IP` and `DBotScore` context.
3. It calls `!ipgeolocation-asn` to add the Autonomous System, its category and its registry, which supports
   infrastructure pivoting.
4. A conditional task branches on the DBotScore written by IPGeolocation.io. When the verdict is Suspicious or
   Malicious, the playbook calls `!ipgeolocation-abuse-contact` so the abuse contact is available to a downstream
   notification or takedown task.
5. The playbook outputs `DBotScore`, the standard `IP` indicator context, `IPGeolocation.IP` and
   `IPGeolocation.ASN`, so a parent playbook can consume them.

Every task is set to tolerate errors, so a private, bogon or unresolvable address does not stop the run. The
playbook uses only commands from this pack, so it adds no pack dependencies.

The playbook is intentionally small and free of vendor specific post processing, so it can be copied and extended.

## Troubleshooting

**The Test button fails with HTTP 401.**
Confirm that the API key is correct and active in the IPGeolocation.io dashboard. A key issued for a database
subscription cannot call the APIs. A paused, expired or past due subscription also answers with 401.

**Test succeeds but the `ip` command returns an Unknown verdict.**
The security object was not returned, which means the subscription does not include IP Security data. IP Security is
a paid feature. The war room entry states this explicitly.

**A command that worked yesterday now returns HTTP 401 for a module.**
Check whether the subscription changed plan or entered a trial expired state. The optional modules (`security`,
`abuse`, `geo_accuracy`, `dma_code`, `user_agent`, `hostname`), domain lookups and non English responses are all
paid features.

**HTTP 423 Locked for an address in an incident.**
The address is a bogon or belongs to a private network, so IPGeolocation.io holds no data for it. Filter internal
ranges before enrichment, or rely on the warning entry and continue.

**HTTP 429 in the middle of a playbook run.**
The quota or the surcharge limit was reached. Review usage in the billing dashboard, and see the Credits and Rate
Limiting section for ways to reduce consumption.

**HTTP 499, or a read timeout error naming the configured timeout.**
The HTTP timeout is too short for the current network path. Increase **HTTP timeout (seconds)**. Requests that
include several optional modules, or a live hostname lookup, take longer than a base lookup.

**The response is not valid JSON.**
A proxy or captive portal is rewriting the response. Verify the server URL and the proxy configuration, and confirm
that the Cortex XSOAR engine can reach `api.ipgeolocation.io` directly over HTTPS.

**A city or region looks wrong.**
Request `include=geo_accuracy` and inspect `Location.AccuracyRadius` and `Location.Confidence`. If the data is
genuinely incorrect, IPGeolocation.io accepts corrections through its data correction form.

## Limitations

- The bulk endpoints are not implemented. Commands that accept a list of IP addresses issue one request per address.
- Caller IP lookup, which the API supports when the `ip` parameter is omitted, is not exposed. In a Cortex XSOAR
  context it would resolve the egress address of the server or engine, which is rarely the intended target, so the
  `ip` argument is required instead.
- XML output is not exposed. The integration always requests the default JSON representation.
- The `ipgeolocation-ip-security` and `ipgeolocation-abuse-contact` commands accept IP addresses only. Domain names
  are supported by `ipgeolocation-ip-lookup`.
- The Time Zone, User Agent and Astronomy APIs are out of scope, although the time zone and parsed user agent data
  available through `/v3/ipgeo` is fully mapped.

## FAQ

**Which command should I use for reputation?**
Use `!ip`. It is the only command that writes a DBotScore, and it is what the standard Cortex XSOAR enrichment flow
calls. The other commands are enrichment only by design, so an investigation can gather context without changing an
indicator verdict.

**Why is the geolocation command not called `ipgeo-location`?**
Because the endpoint behind it returns much more than location. `GET /v3/ipgeo` is a unified endpoint that also
returns network, ASN, company, currency, country metadata and time zone data by default, and can return security,
abuse contact, parsed user agent, geolocation accuracy, DMA code and reverse DNS hostname through `include`. A name
built around the word location would understate the command and would age badly. `ipgeolocation-ip-lookup` names
what the command does, which is a full IP lookup.

**What does `is_anonymous` mean?**
It indicates that the connection arrives over an anonymizing route, that is a VPN, a proxy, a relay or Tor. It is a
convenient single signal, but the individual flags tell you which one, which usually matters for the response.

**Why is a confidence score 0 when the matching flag is false?**
Zero is the documented default for a confidence score when the related detection did not fire. The integration
preserves zero values and `false` values in the context rather than pruning them, so playbook conditions can rely on
them being present.

**Does the integration flag search engine crawlers as bots?**
IPGeolocation.io states that well known search engine crawlers are not flagged, and that `is_bot` is intended to
indicate suspicious or abusive automation. Verify this against your own traffic before you act on it.

**How fresh is the data?**
IPGeolocation.io updates geolocation data every 24 hours, security data at least twice per 24 hours, and ASN and
abuse data daily.

**Can I look up a domain name?**
Yes, with `ipgeolocation-ip-lookup` on a paid plan. The response returns the resolved address in `IP` and the
submitted domain in `Domain`. The Security and Abuse Contact endpoints do not accept domain names.

**Can I look up an ASN directly, without an IP address?**
Yes. `ipgeolocation-asn` accepts either `asn` or `ip`, and the `asn` argument takes both `24940` and `AS24940`.

**Does the integration send my API key anywhere else?**
No. The key is sent only to the configured server URL, as the `apiKey` query parameter documented by
IPGeolocation.io, and Cortex XSOAR masks configured credentials in logs.
