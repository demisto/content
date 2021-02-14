## SplunkPy
Use the SplunkPy integration to fetch incidents from Splunk ES, and query results by SID.
***

### Fetching noteble events.
The integration allows for fetching Splunk notable events using A default query. The query can be changed and modified to support different Splunk use cases.

### Enriching notable events
This integration allows 3 types of enrichments for fetched notables: Drilldown, Asset, and Identity.

#### Enrichment types
1. **Drilldown search enrichment**: fetches the drilldown search configured by the user in the rule name that triggered the notable and performs this search. The results are stored in the context of the incidents under the **Drilldown** field.
2. **Asset search enrichment**: Runs the following query:
`| inputlookup append=T asset_lookup_by_str where asset=$ASSETS_VALUE | inputlookup append=t asset_lookup_by_cidr where asset=$ASSETS_VALUE | rename _key as asset_id | stats values(*) as * by asset_id`
where the **$ASSETS_VALUE** is replaced with the **src**, **dest**, **src_ip** & **dst_ip** from the fetched notable. The results are stored in the context of the incidents under the **Asset** field.
3. **Identity search enrichment**: Runs the following query
`| inputlookup identity_lookup_expanded where identity=$IDENTITY_VALUE`
where the **$IDENTITY_VALUE** is replaced with the **user** & **src_user** from the fetched notable. The results are stored in the context of the incidents under the **Identity** field.

#### How to configure
1. Configure the integration to fetch incidents (see integration documentation for details).
2. `Enrichment Types`: Select the enrichment types you want to enrich each fetched notable with. If none are selected, the integration will fetch notables as usual (without enrichment).
3. `Fetch notable events ES query`: The query for the notable events enrichment (defined by default). If you decide to edit this, make sure to provide a query that uses the \`notable\` macro, use the new default query as an example.  
4.`Enrichment Timeout (Minutes)`:  The timeout for each enrichment (default is 5min). When the selected timeout was reached, notable events that were not enriched will be saved without the enrichment.
5.`Number of Events Per Enrichment Type`: The maximal amount of events to fetch per enrichment type (default to 20).

##### NOTE: The enrichment mechanism uses a new default fetch query. 
This implies that new fetched events might have a slightly different structure than old events fetched so far.
**Users who wish to enrich fetched notables and have already used the integration in the past:** 
1. Might have to slightly change existing logic for some of their custom entities configured for Splunk (Playbooks, Mappers, Pre-Processing Rules, Scripts, Classifiers, etc...) in order for them to work with the modified structure of the fetched events. 
2. Will need to change the `Fetch notable events ES enrichment query` parameter to the following query: 
```search \`notable\` | eval rule_name=if(isnull(rule_name),source,rule_name) | eval rule_title=if(isnull(rule_title),rule_name,rule_title) | `get_urgency` | `risk_correlation` | eval rule_description=if(isnull(rule_description),source,rule_description) | eval security_domain=if(isnull(security_domain),source,security_domain)```

#### Troubelshooting enrichment status
Each enriched incident **may** contain the following fields in the incident context:
- **successful_drilldown_enrichment**: whether the drill down enrichment was successful or not.
- **successful_asset_enrichment**: whether the asset enrichment was successful or not.
- **successful_identity_enrichment**: whether the identity enrichment was successful or not.
- **successful_enrichment**: whether the whole enrichment for the incident was successful or not. Note that this will be set to `True` if and only if all enrichments were successfully finished.

#### Resetting the enriching fetch mechanism
- Run the `splunk-reset-enriching-fetch-mechanism` and the mechanism will be reset to the initial configuration (No need to use the `Last Run` button)

#### Limitations
- As the enrichment process is asynchronous, fetching enriched incidents takes longer. The integration was tested with 20+ notables simultaneously that were fetched and enriched after approximately ~4min.
- If you wish to configure a mapper, wait for the integration to perform the first fetch successfully, this is to make the fetch mechanism logic stable.
- The drill down search, does not support Splunk's advanced syntax. For example: Splunk filters (**|s**, **|h**, etc...)  
