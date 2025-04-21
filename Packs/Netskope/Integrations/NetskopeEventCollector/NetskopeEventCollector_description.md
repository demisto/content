## Netskope Event Collector

### General Info
- Collects events extracted from SaaS traffic and logs.
- The collector collects 5 types of events: 
   - Audit
   - Application
   - Network
   - Alert
   - Page
- Note: The collector can handle up to 35K events per minute on average. 

### API Key
- To generate the API token, in your Netskope UI go to **Settings** > **Tools** > **Rest API v2**
- The KEY requires the following permissions:
  - /api/v2/events/dataexport/events/*
  - /api/v2/events/dataexport/alerts/*
- Visit the [Netskope API Overview](https://docs.netskope.com/en/rest-api-v2-overview-312207.html) for more information.