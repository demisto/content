During an investigation or a vulnerability review, it helps to know whether the version running on an asset is still supported by its vendor, when that support ends, and where the date comes from.

endoflife.ai is an independent service that publishes end-of-life and end-of-support dates, an EOL risk score and CISA Known Exploited Vulnerabilities (KEV) exposure for software and hardware products. Each date is labeled with its source.

## What does this pack do?

The pack contains the endoflife.ai integration, which queries the endoflife.ai API. Use it to:

- Get the lifecycle of a product: each tracked version with its end-of-life date, support status and EOL risk score.
- Check one product version: status, end-of-life date, days until or past end of life, EOL risk score with grade and band, and the extended support date where the vendor publishes one.
- Check a list of product and version pairs in one command, for example the software found on an endpoint.
- See where each end-of-life date comes from: the source label and the source URL that the API returns.
- See whether the CISA KEV component of the EOL risk score is above zero for a product.

## Before you start

The integration needs an endoflife.ai API key. A free API key is available at [https://endoflife.ai/api#free-key](https://endoflife.ai/api#free-key).

The API documentation is at [https://endoflife.ai/api](https://endoflife.ai/api).
