### Vectra XDR Integration

Vectra XDR pack allows the security operations center to create incidents based on prioritized Entities, powered by Vectra AI's Attack Signal Intelligence. This pack enables security teams to synchronize the Vectra XDR Entities with Cortex XSOAR incidents in real time, making it feasible to manage operations from a single place.

This integration was integrated and tested with version 3.3 of Vectra API.

### Instance Configuration

The integration only supports one type of ingestion:

1. Vectra XDR Entity: Fetch active Vectra XDR Entity as an XSOAR incident, including related active detections for each fetched Entity.

#### Vectra XDR Entity

To fetch Vectra XDR Entity follow the next steps:

1. Select Fetches incidents.
2. Under Classifier, select "N/A". 
3. Under Incident type, select "Vectra XDR Entity".
4. Under Mapper (incoming), select "Vectra XDR - Incoming Mapper" for default mapping.
5. Enter connection parameters. (Server URL, Client ID & Client Secret Key)
6. Select SSL certificate validation and Proxy if required.
7. Update "Max Fetch" & "First Fetch Time" based on your requirements.
8. Select the Incident Mirroring Direction:
    1. Incoming - Mirrors changes from the Vectra XDR Entity into the Cortex XSOAR incident.
    2. Outgoing - Mirrors changes from the Cortex XSOAR incident to the Vectra XDR Entity.
    3. Incoming And Outgoing - Mirrors changes both Incoming and Outgoing directions on incidents.
9. Enter the relevant tag name for mirror notes.
**Note:** This value is mapped to the **dbotMirrorTags** incident field in Cortex XSOAR, which defines how Cortex XSOAR handles notes when you tag them in the War Room. This is required for mirroring notes from Cortex XSOAR to Vectra XDR.
10. Provide appropriate values for filtering Entities, such as Entity Type, Prioritization, and Tags. Additionally, specify filters for detections, including Detection Name, Detection Category, and Detection Type.
**Note:** Filters for Entities and Detections are combined using 'OR' logic, while filters
11. Adjust the Urgency Score to categorize Entity severity in Cortex XSOAR. There are three fields for this mapping:
    1. Input a value for 'Low' severity. Scores up to this limit are labelled as Low.
    2. The next value is for 'Medium' severity. Scores up to this limit are labelled as Medium.
    3. The third value is for 'High' severity. Scores up to this limit are labelled as High. Any score above this is marked as 'Critical' severity.

**Notes for mirroring:**

- The mirroring settings apply only for incidents that are fetched after applying the settings.
- When mirroring incidents, you can make changes in Vectra that will be reflected in Cortex XSOAR, or vice versa.
- Any tags removed from the Vectra entity will not be removed in the XSOAR incident, as XSOAR doesn't allow the removal of the tags field via the backend. However, tags removed from the XSOAR incident UI will be removed from the Vectra entity.
- New notes from the XSOAR incident will be created as notes in the Vectra entity. Updates to existing notes in the XSOAR incident will not be reflected in the Vectra entity.
- New notes from the Vectra entity will be created as notes in the XSOAR incident. Updates to existing notes in the Vectra entity will create new notes in the XSOAR incident.
- If a closed XSOAR incident is tied to a specific entity and new detections for that entity arise or existing detections become active again, the incident will be automatically reopened.
- When a XSOAR incident is closed but there are still active detections on the Vectra side, and the entity is subsequently updated, the corresponding XSOAR incident for that entity will be reopened.
- The mirroring is strictly tied to Incident type "Vectra XDR Entity" & Incoming mapper "Vectra XDR - Incoming Mapper". If you want to change or use your custom incident type/mapper then make sure changes related to these are present.
- If you want to use the mirror mechanism and you're using custom mappers, then the incoming mapper must contain the following fields: dbotMirrorDirection, dbotMirrorId, dbotMirrorInstance, dbotMirrorTags.
- To use a custom mapper, you must first duplicate the mapper and update the fields in the copy of the mapper. If you detach the out-of-the-box mapper and make changes to it, the pack does not automatically get updates.
- If you are using a custom incident type, you also need to create custom corresponding incoming mappers.
- Following new fields are introduced in the response to the incident to enable the mirroring:
  - mirror_direction: This field determines the mirroring direction for the incident. It is a required field for XSOAR to enable mirroring support.
  - mirror_tags: This field determines what would be the tag needed to mirror the XSOAR entry out to Vectra XDR. It is a required field for XSOAR to enable mirroring support.
  - mirror_instance: This field determines from which instance the XSOAR incident was created. It is a required field for XSOAR to enable mirroring support.

For more information about this integration, visit [Vectra's knwoledge base](https://support.vectra.ai/s/article/KB-VS-1692).
