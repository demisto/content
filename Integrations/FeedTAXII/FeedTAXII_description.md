TAXII Feed integration is a TAXII client that is built to ingest indicators from TAXII feeds. The integration will fetch new indicators after they are published.

# Connect the TAXII Feed Integration to a TAXII Server
To connect the TAXII Feed integration to a TAXII server you'll need to configure the following parameters.
* **Discovery Service** - Available TAXII services and their use can be communicated via the TAXII Discovery Service. The Discovery Service provides a requester with a list of TAXII Services and how these Services can be invoked.
* **Collection** - A Collection is an interface to a logical repository of CTI objects provided by a TAXII Server. This will usually be the feed name.
* **Username/Passowrd** (Optional) - Username and Password for TAXII servers that require basic authentication. 
* **Subscription ID** (Optional) - TAXII defines Subscription IDs. When a Consumer successfully establishes a subscription on a TAXII Server, the server assigns that
subscription a *Subscription ID* value. From then on, both the Consumer and the Server refer to this subscription in messages using this Subscription ID value.
* **Poll Service** (Optional) - Used by a TAXII Client to request information from a TAXII Server. If not provided, will be fetched from the discovery service.
* **API Key + API Header** (Optional) - API key value and the header name to be presented to the TAXII server for authentication.
