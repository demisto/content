TAXII Feed integration is a TAXII client that ingests indicators from TAXII feeds. The integration will fetch new indicators after they are published.

# Connect the TAXII Feed Integration to a TAXII Server
To connect the TAXII Feed integration to a TAXII server you'll need to configure the following parameters.
* **Discovery Service** - Available TAXII services and their use can be communicated via the TAXII Discovery Service. The Discovery Service provides a requester with a list of TAXII Services and how these Services can be invoked.
* **Collection** - A Collection is an interface to a logical repository of CTI objects provided by a TAXII Server. This will usually be the feed name. If you do not know which collections
are available to you, you can leave it empty and press the Test button. In the error message you will receive a list of available collections for the specified discovery path.
* **Subscription ID** (Optional) - TAXII defines Subscription IDs. When a Consumer successfully establishes a subscription on a TAXII Server, the server assigns that
subscription a *Subscription ID* value. From then on, both the Consumer and the Server refer to this subscription in messages using this Subscription ID value.
* **Poll Service** (Optional) - Used by a TAXII Client to request information from a TAXII Server. If not provided, will be fetched from the discovery service.

# Authentication
* **Username + Password** - Username and Password for TAXII servers that require basic authentication. 
These fields also support the use of API key headers. To use API key headers, specify the header name and value in the following format:
`_header:<header_name>` in the **Username** field and the header value in the **Password** field.


## Step by step configuration
As an example, we'll use the public TAXII threat intelligence feed by Abuse_ch accessible via _Hail a TAXII_. These are the feed instance configuration parameters for our example.

**Indicator Reputation** - Because this is just an example, we can leave the default value. Ordinarily you would set the reputation based on the specific feed's information about what type of indicators they are returning, i.e., whether they are good or bad.

**Source Reliability** - Because this is just an example, we can leave the default value. Ordinarily you would set the reliability according to your level of trust in this feed.

**Indicator Expiration Method** - For this example, we can leave the default value here. Ordinarily you would set the value according to the type of feed you were fetching from. As an example, let's that you are a customer of a Cloud Services provider and you want to add the URLs from which that provider serves up many of the services you use to your network firewall exclusion list. Assuming that that same Cloud Services provider maintains an up-to-date feed of the URLs from which they currently provide service, you would probably want to configure a feed integration instance with this parameter set to `Expire indicators when they disappear from feed` so that you don't continue to mark a given URL with a `Good` reputation after it is no longer being used by your Cloud Services provider.

**Feed Fetch Interval** - For this example, we can leave the default value here.

**Discovery Service** - Enter `http://example.com/taxii-discovery-service`.

**Collection** - Enter `guest.Abuse_ch`.

**Subscription ID** - No need to enter a value here for this example since the TAXII server we are addressing does not require it so we'll leave it blank.

**Username** - Enter `guest`.

**Password** - Enter `guest`.

**Request Timeout** - Let's increase the number to `80` seconds since the request may take a while to complete.

**Poll Service** - We don't have to enter a value here for this example because the poll service will be determined dynamically in the integration code if it is not explicitly provided.

**API Key** - We don't have to enter a value here for this example because the TAXII server we are addressing doesn't require an API key.

**API Header Name** - We don't have to enter a value here for this example because the TAXII server we are addressing doesn't require an API header name.

**First Fetch Time** - Since this example feed isn't very high volume, let's enter `500 days`  to make sure we fetch a sufficient number of indicators.

Click the `Test` button and ensure that a green `Success` message is returned.

Now we have successfully configured an instance for the TAXII threat intelligence feed by Abuse_ch accessible via _Hail a TAXII_, once we enable `Fetches indicators` the instance will start pulling indicators.

By clicking `Mapping` in the integration instance, we can map indicator data returned by the feed to actual indicator fields in Cortex XSOAR.
We can use `Set up a new classification rule` using actual data from the feed.
