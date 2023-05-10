## MISP Feed Help

MISP Feed integration allows you to ingest feeds into TIM via an MISP instance.
To ingest feeds via MISP, you must first configure a MISP instance and have the proper credentials.

To ingest specific feeds (Bambenek Consulting Feed, etc.) directly to TIM without any authorization, you can use one of our dedicated feed content packs available in Marketplace. 

To ingest feeds via a URL, you can use one of the following content packs:
- CSV Feed
- JSON Feed
- Plain Text Feed
- RSS Feed

### How to configure the MISP Feed integration
- Use your MISP instance URL as 'https://x.x.x.x'.
- You can find your API key in **Global Actions** >**My Profile** >**Auth key**>. Click the eye symbol to view your key.

### How to configure your fetch indicators query

- You can enter a list of types and tags. All indicators that are of those tags and types will be returned.
- You can enter a JSON query that will be used as the search query.

JSON query docs can be found at 'https://&lt;Your_MISP_URL&gt;/servers/openapi#operation/restSearchAttributes'.
