## Feedly

Use the Feedly integration to import articles as incidents from your Feedly boards and folders.

**Note** You also need to setup the `FeedFeedly` integration with the same feeds, to ingest entities (intrusion sets, malware, TTPs) as indicators, and relationships between them. The `IncidentsFeedly` integration will work without it, but the incidents will be missing context.

**Disclaimer** You will need the Feedly for Threat Intelligence package to enable this integration. You can learn more about our product here: https://feedly.com/i/landing/threatIntelligence

### Authentication

To generate an API for the application, go to [the api page on your account](https://feedly.com/i/team/api). We highly recommend that you create a separate token for this integration.
