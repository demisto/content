IsMalicious provides indicator enrichment for IPs, domains, full URLs and MD5/SHA1/SHA256 hashes. It returns server evidence, risk and confidence, source context and data-trust information.

Create an account and API credential at https://ismalicious.com/app/account. The integration requires the complete X-API-KEY credential, Base64 of apiKey:apiSecret, not the raw API key alone. Individual checks use the account quota; TAXII feed access is separate.

This integration performs advisory lookups only. It does not ingest a TAXII feed, upload file contents, fetch incidents, or enable an automatic-block policy. Unknown hashes, delisted indicators and responses without a supported verdict return DBotScore 0. If a legacy response lacks the evidence object, explicit malicious=true is accepted as malicious; malicious=false remains unknown. Only explicit server clean/benign evidence can produce good (1). TLS verification is always enabled; redirects and automatic retries are disabled.
