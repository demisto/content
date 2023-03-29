# Cloudflare WAF Pack
Use Cloudflare WAF to manage firewall rules, filters, and IP-lists.

## What does this pack do?

- Create, update, delete or retrieve a new firewall rule.
- Create, update, delete or retrieve a new filter.
- Create, delete or retrieve a new IP-list.
- Create, Replace, delete or retrieve a new IP-list items.
- Retrieve all zones in account.
- Run a pipeline.

This pack contains an integration, whose main purpose is to manage firewall rules in Cloudflare Services.

In addition, this pack includes XSIAM content.

### Collect Events from Cloudflare WAF (XSIAM)

We are currently support the retrieval of events from Cloudflare WAF by using an HTTP Log Collector, and Cloudflare waf logpush v2.

**On XSIAM:**

1. Navigate to **Settings** -> **Data Sources** -> **Add Data Source** -> **Custom - HTTP based Collector** -> Click on **Connect Another Instance**, set the Name and Compression as you choose and then please set:
   - Name as `Cloudflare`
   - Compression `gzip`
   - Log Format as `JSON`
   - Vendor as `cloudflare`
   - Product as `waf`
2. Creating a new HTTP Log Collector will allow you to generate a unique token, please save it since it will be used later.
3. Click the 3 dots sign next to the newly created instance and copy the API Url, it will also be used later.

**On Cloudflare:**

In order to configure the logpush on cloudflare side, please read [this documentation](https://developers.cloudflare.com/logs/get-started/enable-destinations/http/). 

<u>Guidelines:</u>
1. For the **destination_conf**, use the API Url which was copied in section 3 (on the XSIAM side).
2. For the **X-Auth-Key**, use the newly created token mentioned in section 2 (on the XSIAM side).