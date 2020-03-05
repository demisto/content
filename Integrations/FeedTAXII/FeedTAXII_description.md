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


## Step by step configuration
---
As an example, we'll be looking at the public TAXII threat intelligence feed by Abuse_ch accessible via _Hail a TAXII_. These are the feed instance configuration parameters for our example.

**Indicator Reputation** - Because this is just an example, we can leave the default value. Ordinarily you would set the reputation based off the specific feed's information about what type of indicators they are returning, e.g., whether they are good or bad.

**Source Reliability** - Because this is just an example, we can leave the default value. Ordinarily you would set the reliability equal to how much you trusted the feed's source.

**Indicator Expiration Method** - For this example, we can leave the default value here. Ordinarily you would set the value according to the type of feed you were fetching from. As an example, let us say that you are a customer of a Cloud Services provider and you want to add the URLs from which that provider serves up a lot of the services you use to your network firewall exclusion list. Assuming that that same Cloud Services provider maintains an up-to-date feed of the URLs from which they currently provide service, you would probably want to configure a feed integration instance with this parameter set to `Expire indicators when they disappear from feed` so that you don't continue to mark a given URL with a `Good` reputation after it is no longer being used by your Cloud Services provider.

**Feed Fetch Interval** - For this example, we can leave the default value here.

**Discovery Service** - Enter `http://hailataxii.com/taxii-discovery-service`.

**Collection** - Enter `guest.Abuse_ch`

**Subscription ID** - No need to enter a value here for this example since the TAXII server we are addressing does not require it so we'll leave it blank.

**Username** - Enter `guest`.

**Password** - Enter `guest`.

**Request Timeout** - Let's increase the number to `80` since the request may take a while complete.

**Poll Service** - No need to enter a value here for this example because the poll service will be determined dynamically in the integration code if it is not explicitly provided here so we'll leave it blank.

**API Key** - No need to enter a value here for this example because the TAXII server we are addressing doesn't require it so we'll leave it blank.

**API Header Name** - No need to enter a value here for this example because the TAXII server we are addressing doesn't require it so we'll leave it blank.

**First Fetch Time** - Since this example feed isn't very high volume let's enter `500 days`  to make sure we fetch a good number of indicators.

Click the `Test` button and ensure that a green `Success` message is returned.

Now we have successfully configured an instance for the TAXII threat intelligence feed by Abuse_ch accessible via _Hail a TAXII_, once we enable `Fetches indicators` the instance will start pulling indicators.

By clicking `Mapping` in the integration instance, we can map indicator data returned by the feed to actual indicator fields in Cortex XSOAR.
We can use `Set up a new classification rule` using actual data from the feed.