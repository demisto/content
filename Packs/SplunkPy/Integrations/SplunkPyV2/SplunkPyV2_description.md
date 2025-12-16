## SplunkPy v2

Use the SplunkPy v2 integration to:

- Fetch events (logs) from Splunk into Cortex
- Push events from Cortex to Splunk
- Fetch Splunk Enterprise Security events (Findings) into Cortex.
***

## Authentication Configuration

This integration uses **Splunk token-based authentication**.

### How to Create a Splunk Authentication Token
1. Log in to your Splunk instance as an administrator
2. Navigate to **Settings** > **Tokens** (or **Settings** > **Users and Authentication** > **Tokens**)
3. Click **New Token** or **Enable Token Authentication** (if not already enabled)
4. Provide a name for the token and set an expiration time (optional)
5. Click **Create** and copy the generated token immediately (it will only be shown once)
6. Use this token value in the integration's **Splunk Token** field

For detailed instructions, refer to the official Splunk documentation:
- [Create authentication tokens in Splunk Cloud](https://docs.splunk.com/Documentation/SplunkCloud/latest/Security/CreateAuthTokens)
- [Create authentication tokens in Splunk Enterprise](https://docs.splunk.com/Documentation/Splunk/latest/Security/UseAuthTokens)



There are two main use cases for the SplunkPy v2 integration.
- [Splunk Enterprise Security Users](https://xsoar.pan.dev/docs/reference/integrations/splunk-py#splunk-enterprise-security-users)
  - [Fetching finding events](https://xsoar.pan.dev/docs/reference/integrations/splunk-py#fetching-finding-events)
  - [Enriching Finding Events](https://xsoar.pan.dev/docs/reference/integrations/splunk-py#enriching-finding-events)
  - [Incident Mirroring](https://xsoar.pan.dev/docs/reference/integrations/splunk-py#incident-mirroring)
- [Splunk non-Enterprise Security Users](https://xsoar.pan.dev/docs/reference/integrations/splunk-py#splunk-non-enterprise-security-users)
  - [Configure Splunk to Produce Alerts for SplunkPy v2 for non-ES Splunk Users](https://xsoar.pan.dev/docs/reference/integrations/splunk-py#configure-splunk-to-produce-alerts-for-splunkpy-for-non-es-splunk-users)
  - [Constraints](https://xsoar.pan.dev/docs/reference/integrations/splunk-py#constraints)

***
# Splunk Enterprise Security Users

## Fetching finding events
The integration allows for fetching Splunk finding events using a default query. The query can be changed and modified to support different Splunk use cases.
Palo Alto highly recommends reading the [Ingest Incidents from a SIEM Using Splunk article](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Tutorials-6.x/Ingest-Incidents-from-a-SIEM-Using-Splunk) before starting to use this integration.
This article will help you configure your Splunk v2 integration, set up a basic flow, and start ingesting incidents from Splunk to Cortex XSOAR/XSIAM.

### How to configure
1. Navigate to one of the following:
    * Cortex XSOAR 8: Settings & Info > Settings > Integrations > Instances > SplunkPy v2
    * Cortex XSOAR 6: Settings > Integrations > Servers & Services > SplunkPy v2.
    * Cortex XSIAM: Settings > Configurations > Automation & Feed Integrations> SplunkPy v2```
2. Click **Add Instance**.
3. Type the **Server URL** and **Splunk Token**.
4. Select **Fetches incidents**.
5. Under Classifier, select N/A.
6. Under Incident Type, select **Splunk Finding**.
You do not need to specify the classifier as all Splunk incidents are ingested as Splunk Finding. As you become more familiar with Cortex XSOAR/XSIAM, you can create custom incident types as needed instead of using the Splunk Finding incident type.
7. Under Mapper (incoming), select **Splunk Finding - Incoming Mapper**.
8. Under Mapper (outgoing), select **Splunk Finding - Outgoing Mapper**.
9. Keep the **Fetch events query** as is, as we use the \`notable\` macro when ingesting events. You can create a more granular search by specifying specific conditions such as specific security domain, event ID, etc.
10. Keep the defaults for fetch limit, first fetch timestamp.
11. To add mirroring in both environments, in the Incident Mirroring Direction field, select **Incoming and Outgoing**.
Outgoing mirroring is recommended for Cortex XSOAR version 6.2 and above.
12. Select *Close Mirrored XSOAR Incident* and *Close Mirrored Splunk Finding Event*, so when closing in one environment, it closes in the other.
13. In the Enrichment Types field, select *Asset*, *Drilldown* and *Identity*.
This enrichment provides additional information about assets, drilldown, and identities that are related to the finding events you ingest. 
For more information, see [Enriching Finding Events](#enriching-finding-events).
14. Fetch backwards window - this backward window is for cases where there is a gap between the event occurrence time and the event index time on the Splunk server.
In Splunk, there is often a delay between the time an incident is created (the event's "occurrence time") and the time it is actually searchable in Splunk and visible in the index (the event's "index time").
This delay can be caused by an inefficient Splunk architecture, causing higher event indexing latency. However, it can also be "by design", e.g., if some endpoints / machines that generate Splunk events are usually offline.
Another point to note is that Splunk's searches are based on the occurrence time behind the scenes. Meaning, Splunk itself uses occurrence time as its determining factor for bucket division and search.
Therefore, we can't use index time as our primary search key without making the searches inefficient.
The backwards window is a way for you to configure the longest delay you would like to support.
This parameter determines the size of the occurrence time "sliding window" we will support in our queries. For example, if set for 2 hours, we will always search for events that occurred up to 2 hours ago (and will of course ignore duplicates).
However, there is obviously a price - the larger the window, the longer it will take for fetch queries to complete.
The best value to set depends on the delays that you see in your system (consult with your Splunk expert / master), the number of events in your system, and other network properties.
Use this parameter with careful consideration.
15. Click **Test** and then **Save & exit**.

**Note: If you are using a custom incident type, you also need to create custom corresponding incoming and outgoing mappers.**

**Important: If you want to use the mirror mechanism, the incoming mapper must contain the following fields: dbotMirrorDirection, dbotMirrorId, dbotMirrorInstance**

### Enriching Finding Events
This integration allows 3 types of enrichments for fetched findings: Drilldown, Asset, and Identity.

#### Enrichment types
1. **Drilldown search enrichment**: Fetches the drilldown searches configured by the user in the rule name that triggered the finding event and performs this search. The results are stored in the context of the incident under the **Drilldown** field as follows: [{'query_name':<query_name>, 'query_search': <query_search>, 'query_results': [{result1}, {result2}, {result3}], 'enrichment_status': <enrichment_status>}].
2. **Asset search enrichment**: Runs the following query:
*`| inputlookup append=T asset_lookup_by_str where asset=$ASSETS_VALUE | inputlookup append=t asset_lookup_by_cidr where asset=$ASSETS_VALUE | rename _key as asset_id | stats values(*) as * by asset_id`*
where the **$ASSETS_VALUE** is replaced with the **src**, **dest**, **src_ip** and **dst_ip** from the fetched finding. The results are stored in the context of the incident under the **Asset** field.
3. **Identity search enrichment**: Runs the following query
*`| inputlookup identity_lookup_expanded where identity=$IDENTITY_VALUE`*
where the **$IDENTITY_VALUE** is replaced with the **user** and **src_user** from the fetched finding event. The results are stored in the context of the incident under the **Identity** field.

#### How to configure
1. Configure the integration to fetch incidents (see the Integration documentation for details).
2. *Enrichment Types*: Select the enrichment types you want to enrich each fetched finding with. If none are selected, the integration will fetch findings as usual (without enrichment).
3. *Fetch finding events ES query*: The query for the finding events enrichment (defined by default). If you decide to edit this, make sure to provide a query that uses the \`notable\` macro. See the default query as an example.
4. *Enrichment Timeout (Minutes)*:  The timeout for each enrichment (default is 5min). When the selected timeout was reached, finding events that were not enriched will be saved without the enrichment.
5. *Number of Events Per Enrichment Type*: The maximal amount of events to fetch per enrichment type (Drilldown, Asset, and Identity). In a case of multiple drilldown enrichments the limit will apply for each drilldown search query. (default to 20).

#### Troubleshooting enrichment status
Each enriched incident contains the following fields in the incident context:
- **successful_drilldown_enrichment**: whether the drilldown enrichment was successful. In a case of multiple drilldown enrichments, the status is successful if at least one drilldown search enrichment was successful.
- **successful_asset_enrichment**: whether the asset enrichment was successful.
- **successful_identity_enrichment**: whether the identity enrichment was successful.

#### Resetting the enriching fetch mechanism
- Click the ***Reset the "last run"*** button
- Run the ***splunk-reset-enriching-fetch-mechanism*** command and the mechanism will be reset to the initial configuration.

#### Limitations
- As the enrichment process is asynchronous, fetching enriched incidents takes longer. The integration was tested with 20+ notables simultaneously that were fetched and enriched after approximately ~4min.
- If you wish to configure a mapper, wait for the integration to perform the first fetch successfully. This is to make the fetch mechanism logic stable.
- The drilldown search does not support Splunk's advanced syntax. For example: Splunk filters (**|s**, **|h**, etc.)

### Incident Mirroring
**Important Notes**
 - This feature is available from Cortex XSOAR version 6.0.0.
 - This feature is supported by Splunk Enterprise Security only.
 - In order for the mirroring to work, the *Incident Mirroring Direction* parameter needs to be set before the incident is fetched.
 - In order to ensure the mirroring works as expected, mappers are required, both for incoming and outgoing, to map the expected fields in Cortex XSOAR and Splunk.
 - For mirroring the *owner* field, the usernames need to be transformed to the corresponding names in Cortex XSOAR and Splunk.

You can enable incident mirroring between Cortex XSOAR incidents and Splunk findings.
To set up mirroring:
1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for SplunkPy v2 and select your integration instance.
3. Enable **Fetches incidents**.
4. You can go to the *Fetch finding events ES enrichment query* parameter and select the query to fetch the findings from Splunk. Make sure to provide a query which uses the \`notable\` macro, See the default query as an example.
5. In the *Incident Mirroring Direction* integration parameter, select in which direction the incidents should be mirrored:
    - Incoming - Any changes in Splunk findings (finding's status, status_label, urgency, comments, and owner) will be reflected in Cortex XSOAR incidents.
    - Outgoing - Any changes in Cortex XSOAR incidents (finding's status (not status_label), urgency, comments, and owner) will be reflected in Splunk findings.
    - Incoming And Outgoing - Changes in Cortex XSOAR incidents and Splunk findings will be reflected in both directions.
    - None - Turns off incident mirroring.
6. Optional: Check the *Close Mirrored Cortex XSOAR Incidents (Incoming Mirroring)* integration parameter to close the Cortex XSOAR incident when the corresponding finding is closed on the Splunk side.
   By default, only Findings closed with a "Closed" label will be mirrored. You can specify specific statuses (comma-separated) in the *Additional Splunk status labels to close on mirror (Incoming Mirroring)*, and enable the *Enable Splunk statuses marked as "End Status" to close on mirror (Incoming Mirroring)* option to add statuses marked as "End Status" in Splunk, and to add additional statuses to the mirroring process.
7. Optional: Check the *Close Mirrored Splunk Finding Event* integration parameter to close the Splunk finding when the corresponding Cortex XSOAR incident is closed.
**Note: This will not affect existing incidents.**


# Splunk non-Enterprise Security Users

### Configure Splunk to Produce Alerts for SplunkPy v2 for non-ES Splunk Users

Palo Alto recommends that you configure Splunk to produce basic alerts that the SplunkPy v2 integration can ingest, by creating a summary index in which alerts are stored. The SplunkPy v2 integration can then query that index for incident ingestion. It is not recommended to use the Cortex XSOAR application with Splunk for routine event consumption because this method is not able to be monitored and is not scalable.

1. Create a summary index in Splunk. For more information, click [here](https://docs.splunk.com/Documentation/Splunk/7.3.0/Indexer/Setupmultipleindexes#Create_events_indexes_2).
2. Build a query to return relevant alerts.
![image](../../doc_files/build-query.png)
1. Identify the fields list from the Splunk query and save it to a local file.
![image](../../doc_files/identify-fields-list.png)
1. Define a search macro to capture the fields list that you saved locally. For more information, click [here](https://docs.splunk.com/Documentation/Splunk/7.3.0/Knowledge/Definesearchmacros).
Use the following naming convention: (demisto_fields_{type}).
![image](../../doc_files/micro-name.png)
![image](../../doc_files/macro.png)
1. Define a scheduled search, the results of which are stored in the summary index. For more information about scheduling searches, click [here](https://docs.splunk.com/Documentation/Splunk/7.3.0/Knowledge/Definesearchmacros).
![image](../../doc_files/scheduled-search.png)
1. In the Summary indexing section, select the summary index, and enter the {key:value} pair for Cortex XSOAR classification.
![image](../../doc_files/summary-index.png)
1. Configure the incident type in Cortex XSOAR by navigating to __Settings > Advanced > Incident Types.__ Note: In the example, Splunk Generic is a custom incident type.
![image](../../doc_files/incident_type.png)
1. Configure the classification. Make sure that your non ES incident fields are associated with your custom incident type.
   1. Navigate to __Settings > Integrations > Classification & Mapping__.
   2. Click your classifier.
   3. Select your instance.
   4. Click the fetched data.
   5. Drag the value to the appropriate incident type.
![image](../../doc_files/classify.png)
1. Configure the mapping. Make sure to map your non ES fields accordingly and make sure that these incident fields are associated with their custom incident type.
   1. Navigate to __Settings > Integrations > Classification & Mapping__.
   2. Click your mapper.
   3. Select your instance.
   4. Click the __Choose data path__ link for the field you want to map.
   5. Click the data from the Splunk fields to map it to Cortex XSOAR.
![image](../../doc_files/mapping.png)
1.  (Optional) Create custom fields.
2.  Build a playbook and assign it as the default for this incident type.

### Constraints
The following features are not supported in non-ES (Enterprise Security) Splunk.
- Incident Mirroring
- Enrichment.
- Content in the Splunk content pack (such as mappers, layout, playbooks, incident fields, and the incident type). Therefore, you will need to create your own content. See the [Cortex XSOAR Administrator’s Guide](https://docs-cortex.paloaltonetworks.com/p/XSOAR) for information.
