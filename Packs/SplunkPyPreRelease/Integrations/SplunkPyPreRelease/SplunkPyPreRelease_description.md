## SplunkPy Pre Release
Use the SplunkPy Pre Release integration to fetch incidents from Splunk ES, and query results by SID.
This is a pre-release version, that should be used mainly for fetching incidents at this point (July 2021).
The changes in this version will be added to the official release in a few months.
***

To use Splunk token authentication, enter the text: *_token* in the **Username** field and your token value in the **Password** field.
To create an authentication token, go to [Splunk create authentication tokens](https://docs.splunk.com/Documentation/SplunkCloud/8.1.2101/Security/CreateAuthTokens).
***

### Fetching notable events.
The integration allows for fetching Splunk notable events using a default query. The query can be changed and modified to support different Splunk use cases. (See [Existing users](#existing-users)).

### Enriching notable events
This integration allows 3 types of enrichments for fetched notables: Drilldown, Asset, and Identity.

#### Enrichment types
1. **Drilldown search enrichment**: fetches the drilldown search configured by the user in the rule name that triggered the notable event and performs this search. The results are stored in the context of the incident under the **Drilldown** field.
2. **Asset search enrichment**: Runs the following query:
*| inputlookup append=T asset_lookup_by_str where asset=$ASSETS_VALUE | inputlookup append=t asset_lookup_by_cidr where asset=$ASSETS_VALUE | rename _key as asset_id | stats values(*) as * by asset_id*
where the **$ASSETS_VALUE** is replaced with the **src**, **dest**, **src_ip** and **dst_ip** from the fetched notable. The results are stored in the context of the incident under the **Asset** field.
3. **Identity search enrichment**: Runs the following query
*`| inputlookup identity_lookup_expanded where identity=$IDENTITY_VALUE*
where the **$IDENTITY_VALUE** is replaced with the **user** and **src_user** from the fetched notable event. The results are stored in the context of the incident under the **Identity** field.

#### How to configure
1. Configure the integration to fetch incidents (see the Integration documentation for details).
2. *Enrichment Types*: Select the enrichment types you want to enrich each fetched notable with. If none are selected, the integration will fetch notables as usual (without enrichment).
3. *Fetch notable events ES query*: The query for the notable events enrichment (defined by default). If you decide to edit this, make sure to provide a query that uses the \`notable\` macro. See the default query as an example.  
4. *Enrichment Timeout (Minutes)*:  The timeout for each enrichment (default is 5min). When the selected timeout was reached, notable events that were not enriched will be saved without the enrichment.
5. *Number of Events Per Enrichment Type*: The maximal amount of events to fetch per enrichment type (default to 20).

#### Troubleshooting enrichment status
Each enriched incident contains the following fields in the incident context:
- **successful_drilldown_enrichment**: whether the drill down enrichment was successful.
- **successful_asset_enrichment**: whether the asset enrichment was successful.
- **successful_identity_enrichment**: whether the identity enrichment was successful.

#### Resetting the enriching fetch mechanism
Run the ***splunk-reset-enriching-fetch-mechanism*** command and the mechanism will be reset to the initial configuration. (No need to use the **Last Run** button).

#### Limitations
- As the enrichment process is asynchronous, fetching enriched incidents takes longer. The integration was tested with 20+ notables simultaneously that were fetched and enriched after approximately ~4min.
- If you wish to configure a mapper, wait for the integration to perform the first fetch successfully. This is to make the fetch mechanism logic stable.
- The drilldown search, does not support Splunk's advanced syntax. For example: Splunk filters (**|s**, **|h**, etc.)  

### Incident Mirroring
**NOTE: This feature is available from Cortex XSOAR version 6.0.0**
**NOTE: This feature is supported by Splunk Enterprise Security only**

You can enable incident mirroring between Cortex XSOAR incidents and Splunk notables.
To setup the mirroring follow these instructions:
1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for SplunkPy and select your integration instance.
3. Enable **Fetches incidents**.
4. You can go to the *Fetch notable events ES enrichment query* parameter and select the query to fetch the notables from Splunk. Make sure to provide a query which uses the \`notable\` macro, See the default query as an example.
4. In the *Incident Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:
    - Incoming - Any changes in Splunk notables (notable's status, status_label, urgency, comments, and owner) will be reflected in XSOAR incidents.
    - Outgoing - Any changes in XSOAR incidents (notable's status (not status_label), urgency, comments, and owner) will be reflected in Splunk notables.
    - Incoming And Outgoing - Changes in XSOAR incidents and Splunk notables will be reflected in both directions.
    - None - Turns off incident mirroring.
5. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding notable is closed on Splunk side.
6. Optional: Check the *Close Mirrored Splunk Notable Event* integration parameter to close the Splunk notable when the corresponding Cortex XSOAR incident is closed.
7. Fill in the **timezone** integration parameter with the timezone the Splunk Server is using.
Newly fetched incidents will be mirrored in the chosen direction.
Note: This will not effect existing incidents.

### Existing users
**NOTE: The enrichment and mirroring mechanisms use a new default fetch query.** 
This implies that new fetched events might have a slightly different structure than old events fetched so far.
Users who wish to enrich or mirror fetched notables and have already used the integration in the past:
1. Might have to slightly change the existing logic for some of their custom entities configured for Splunk (Playbooks, Mappers, Pre-Processing Rules, Scripts, Classifiers, etc.) in order for them to work with the modified structure of the fetched events. 
2. Will need to change the *Fetch notable events ES enrichment query* integration parameter to the following query (or a fetch query of their own that uses the \`notable\` macro): 

```
search `notable` | eval rule_name=if(isnull(rule_name),source,rule_name) | eval rule_title=if(isnull(rule_title),rule_name,rule_title) | `get_urgency` | `risk_correlation` | eval rule_description=if(isnull(rule_description),source,rule_description) | eval security_domain=if(isnull(security_domain),source,security_domain)
```

Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.
