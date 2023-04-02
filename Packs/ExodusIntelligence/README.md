**Exodus Intelligence’s unmatched vulnerability research capabilities and products provide unique context around your enterprise infrastructure allowing you to better prioritize protection and mitigation efforts. This rich context in conjunction with Cortex XSOAR enables many value-add use cases for alerting and contextual enrichment that would otherwise not be possible.**

**Some example use cases include:**
- Alert on first time an internal host connects to a host on a vulnerable port 
- Alert when unexpected values are passed to vulnerable code 
- On incident creation enrich case with vulnerability mitigation steps 
- Based on an alert regarding a targeted vulnerability, query for alerts related to other hosts with that same vulnerability (or relevant CPE) 

**To access Exodus Intelligence’s powerful vulnerability dataset via Cortex XSOAR, please contact** [Exodus Intelligence](mailto:sales@exodusintel.com).

The EVE integration allows you to retrieve vulnerabilities using the Exodus Intelligence API. A new indicator of type Exodus Intelligence will be created for each vulnerability retrieved.

Please note that an Exodus Intelligence account is necessary to access the API. Please visit https://vpx.exodusintel.com and create an account.

## Required fields:
- Email
- Password
- Private key 

## Optional fields:
- Min XI Score
- Max XI Score

## Available Commands:
!exodus-get-indicators: Runs the integration
!exodus-reset-data-stream: Reset the integration data stream to a later date. Ie: `!exodus-reset-data-stream reset=100` will reset the data stream 100 days in the past.