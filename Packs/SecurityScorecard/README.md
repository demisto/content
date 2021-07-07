# SecurityScorecard Cortex XSOAR Integration

## Use Cases

* Fetch alerts impacting customer's ScoreCard as incidents.
* Interact with incidents (e.g. closure, reply to alerts, etc.)
* Import Score (including trend, and detailed scores per security category.)
* Query Score and alerts from third party and specific portfolios.

---

## Service Overview

[Site](https://securityscorecard.com/) | [API reference](https://securityscorecard.readme.io/reference) | [Available integrations](https://securityscorecard.com/hub/integrations) | [Marketplace](https://securityscorecard.com/product/marketplace) | [Platform](https://platform.securityscorecard.io/#/my-settings/api)

### Products

#### **[Ratings](https://securityscorecard.com/product/security-ratings)**

A-F ratings across risk factors including:

* **DNS health**: Measurement of DNS configuration presence.

* **IP Reputation**: Quantity and duration of malware infections.

* **Web Application Security**: Found web app vulnerabilities such `XSS/SQLi`.

* **Hacker Chatter**: Collection of communications from multiple streams of underground chatter, including hard-to-access or private hacker forums.
* **Endpoint Security**: Protection involved regarding an organization’s devices that access that company’s network.
* **Patching Cadence**: How diligently a company is patching its operating systems.
* **Cubit Score**: Measures a collection of critical security and configuration issues related to exposed administrative portals.

##### Use Cases

* Give security team comprehensive visibility of network and system vulnerabilities from a hacker’s perspective.
* Identify cybersecurity issues across ecosystem.
* Company due diligence.

### Terminology

| Term                | Description                                                     |
|---------------------|-----------------------------------------------------------------|
| Portfolio           | Object holding multiple organizations                           |
| Score               | Scorecard for organization                                      |
| Event Log           | Historical events about organization                            |
| Active Findings     | Current findings about organization specific vulnerabilities    |
| Historical Findings | Historical findings about organization specific vulnerabilities |
| Alert               | Notifications sent based on configured criteria                 |
| Fourth Party        | All services used by an organization                            |
---

#### Relationships

![couldn't load image](https://files.readme.io/e2d5e4a-API_resources.png)

### API

* [Docs](https://platform.securityscorecard.io/docs/index.html)

* [Ratings](https://securityscorecard.readme.io/reference)

* [Guide](https://securityscorecard.readme.io/docs/getting-started)

#### Authorization

Create API key in [My Settings > API](https://platform.securityscorecard.io/#/my-settings/api).

Add API key to header:

```bash
curl -X GET \
  https://api.securityscorecard.io/portfolios \
  -H 'authorization: Token <your API key>'
```

#### Pagination

Requests that list entries in a collection can require pagination to navigate a large number of entries.
When a request support pagination it will respond with a Link http header.

This header includes a link to "next" page of entries, unless on the last page (use this to determine the end of the collection).

```http
https://api.securityscorecard.io/companies/example.com/...; rel="next"
```

It's very important to follow these urls to traverse collections instead of constructing urls on your own. Doing so will protect your integration from future changes.

In some cases when a collection exceeds a certain size, we'll offer instead a report to asynchronously generate a dump of the entire collection.

An example of this is to [Generate a Full Scorecard report](https://securityscorecard.readme.io/reference-link/post_reports-full-scorecard-json) to dump all issue findings on a scorecard.

#### Rate Limits

API requests are limited to **5000 per hour**. If an operation has stricter limits it will be specified on the documentation of that endpoint.

If you reach the limit you'll be temporarily blocked and receive a response with:

```plaintext
HTTP status 429
```

`Retry-After` HTTP header indicating the seconds to wait until next request.
