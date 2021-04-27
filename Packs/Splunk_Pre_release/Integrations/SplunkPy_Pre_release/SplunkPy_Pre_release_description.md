## SplunkPy
Use the SplunkPy integration to fetch incidents from Splunk ES, and query results by SID.
***

To use Splunk token authentication, enter the text: *_token* in the **Username** field and your token value in the **Password** field.
To create an authentication token, go to [Splunk create authentication tokens](https://docs.splunk.com/Documentation/SplunkCloud/8.1.2101/Security/CreateAuthTokens).
***

### Fetching notable events.
The integration allows for fetching Splunk notable events using a default query. The query can be changed and modified to support different Splunk use cases. (See [Existing users](#existing-users)).

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
    - Incoming - Any changes in Splunk notables will be reflected in XSOAR incidents.
    - Outgoing - Any changes in XSOAR incidents (notable's status, urgency, comments, and owner) will be reflected in Splunk notables.
    - Incoming And Outgoing - Changes in XSOAR incidents and Splunk notables will be reflected in both directions.
    - None - Turns off incident mirroring.
5. Optional: Check the *Close Mirrored XSOAR Incident* integration parameter to close the Cortex XSOAR incident when the corresponding notable is closed on Splunk side.
6. Optional: Check the *Close Mirrored Splunk Notable Event* integration parameter to close the Splunk notable when the corresponding Cortex XSOAR incident is closed.
7. Fill in the **timezone** integration parameter with the timezone the Splunk Server is using.
Newly fetched incidents will be mirrored in the chosen direction.
Note: This will not effect existing incidents.
