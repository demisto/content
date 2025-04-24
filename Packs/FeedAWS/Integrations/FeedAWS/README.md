## Overview
---

Use the AWS feed integration to fetch indicators from the feed.


## Configure AWS Feed on Cortex XSOAR
---

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for SpamhausFeed.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __Services__: Services of AWS to fetch indicators from: 
        * AMAZON - All AMAZON ranges.
        * EC2 - EC2 ranges.
        * ROUTE53 - ROUTE53 ranges. 
        * ROUTE53_HEALTHCHECKS - ROUTE53_HEALTHCHECKS ranges.
        * CLOUDFRONT - CLOUDFRONT ranges.
        * S3 - S3 ranges.
        * AMAZON_APPFLOW - AMAZON_APPFLOW ranges.
        * AMAZON_CONNECT - AMAZON_CONNECT ranges.
        * API_GATEWAY - API_GATEWAY ranges.
        * CHIME_MEETINGS - CHIME_MEETINGS ranges.
        * CHIME_VOICECONNECTOR - CHIME_VOICECONNECTOR ranges.
        * CLOUD9 - CLOUD9 ranges.
        * CLOUDFRONT_ORIGIN_FACING - CLOUDFRONT_ORIGIN_FACING ranges.
        * CODEBUILD - CODEBUILD ranges.
        * DYNAMODB - DYNAMODB ranges.
        * EBS - EBS ranges.
        * EC2_INSTANCE_CONNECT - EC2_INSTANCE_CONNECT ranges.
        * GLOBALACCELERATOR - GLOBALACCELERATOR ranges.
        * KINESIS_VIDEO_STREAMS - KINESIS_VIDEO_STREAMS ranges.
        * ROUTE53_HEALTHCHECKS_PUBLISHING - ROUTE53_HEALTHCHECKS_PUBLISHING ranges.
        * ROUTE53_RESOLVER - ROUTE53_RESOLVER ranges.
        * WORKSPACES_GATEWAYS - WORKSPACES_GATEWAYS ranges.
    * __Fetch indicators__: boolean flag. If set to true will fetch indicators.
    * __Fetch Interval__: Interval of the fetches.
    * __Reliability__: Reliability of the feed.  
    * __Traffic Light Protocol color__: The Traffic Light Protocol (TLP) designation to apply to indicators fetched from the feed. More information about the protocol can be found at https://us-cert.cisa.gov/tlp
    * __Skip Exclusion List__: When selected, the exclusion list is ignored for indicators from
    this feed. This means that if an indicator from this feed is on the exclusion
    list, the indicator might still be added to the system. 
    * __Enrichment Excluded__: Select this option to exclude the fetched indicators from the enrichment process.
    * __Indicator reputation__: Indicators from this integration instance will be marked with this
    reputation.
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.
