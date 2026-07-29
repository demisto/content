Enrich IP addresses with geolocation, network, ASN, abuse contact and threat intelligence data from the
IPGeolocation.io v3 APIs.

### Get your API key

1. Sign in to the [IPGeolocation.io dashboard](https://app.ipgeolocation.io/login).
2. Copy the API key from the dashboard, or create a new one.
3. Paste it into the **API Key** field below. Storing the key in the Cortex XSOAR credentials manager is
   recommended.

### Plan requirements

The **Test** button calls `GET /v3/ipgeo` for the sample address `8.8.8.8` and works on the Free plan. A successful
test therefore confirms the API key, but not that the paid modules are enabled on your subscription.

A paid subscription is required for the following.

* The `ip` reputation command and the `ipgeolocation-ip-security` command, because IP Security data is a paid
  feature.
* The `ipgeolocation-abuse-contact` and `ipgeolocation-asn` commands.
* The optional modules of `ipgeolocation-ip-lookup` (`security`, `abuse`, `geo_accuracy`, `dma_code`, `user_agent`,
  `hostname`, `liveHostname`, `hostnameFallbackLive`), domain name lookups and non English responses.

Requests that ask for a paid feature with a Free plan key are answered by the API with HTTP 401.

### Credit usage

IPGeolocation.io bills per credit. A base geolocation lookup costs 1 credit, the security module adds 2 credits and
the abuse contact module adds 1 credit. With its default settings the `ip` command consumes 3 credits per IP
address. Clear **Include geolocation context in the ip command** to reduce that to 2 credits.

For full details, see the
[IPGeolocation.io API documentation](https://ipgeolocation.io/documentation.html).
