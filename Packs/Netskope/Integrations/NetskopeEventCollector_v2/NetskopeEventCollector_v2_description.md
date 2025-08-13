## Netskope Event Collector v2

### General Info
- Collects events extracted from SaaS traffic and logs.
- The NetskopeEventCollector_v2 collector collects 5 types of events: 
   - Audit
   - Application
   - Network
   - Alert
   - Page
- Note: The collector's capacity is at least 150,000 events per minute.

### API Key
- To generate the API token, in your Netskope UI go to **Settings** > **Tools** > **Rest API v2**
- The KEY requires the following permissions:
  - /api/v2/events/data/* (for audit, application, network, alert, and page events)
  - /api/v2/events/datasearch/incident (for incident events)
- Visit the [Netskope API Overview](https://docs.netskope.com/en/rest-api-v2-overview-312207.html) for more information.