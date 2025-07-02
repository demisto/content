## Darktrace
To configure the connection to your Darktrace instance, you will provide:
- Server URL of Darktrace and any necessary proxy information.
- Public and Private API Tokens from Darktrace. Follow the Per-User Token [instructions here](https://customerportal.darktrace.com/product-guides/main/api-tokens). Note that you will need the following permissions for your API tokens: Email logs and Manual Action. 

Best Practices: 
- Ingest both actioned and un-actioned emails. Ingesting the un-actioned emails will give you the ability to manually hold them.
- If you want to reduce the volume of emails ingested then we recommend starting with only inbound emails. Consider adding internal and outbound later on.
- Ingest emails with all Darktrace Tag Severity levels.