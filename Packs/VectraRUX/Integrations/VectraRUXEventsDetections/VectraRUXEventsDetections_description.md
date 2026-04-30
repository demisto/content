### Vectra AI Detection Intelligence Integration

Ingests Vectra AI detections as Cortex XSOAR incidents enriched with entity-level risk prioritization from Attack Signal Intelligence. Priority is persistent and updates as threats evolve - high-risk detections stay surfaced until resolved. Bidirectional synchronization keeps incident state aligned across both platforms in real time.

This integration was integrated and tested with version 3.5 of Vectra API.

### Instance Configuration

To fetch Vectra RUX Events Detections follow the next steps:

1. Select Fetches incidents.
2. Under Classifier, select "N/A".
3. Under Incident type, select "Vectra RUX Events Detection".
4. Under Mapper (incoming), select "Vectra RUX - Incoming Mapper" for default mapping.
5. Enter connection parameters. (Server URL, Client ID & Client Secret Key)
6. Update "Max Fetch" & "First Fetch Time" based on your requirements.
7. Filter the Detections by the "Entity Type"(Account and Host).
8. Filter the Detections by "Create Incidents for Prioritized Detections", "Create Incidents for Escalated Detections":
    1. **Default Behavior**: By default, the integration retrieves all event detections across all entity types (Account and Host) and all detection statuses (Open, Acknowledged, Escalated, Paused). This includes both prioritized and non-prioritized detections.
    2. **Fetch Only Prioritized Detections**: Enable "Create Incidents for Prioritized Detections" to filter out non-prioritized detections. Incidents will be created only for prioritized event detections.
    3. **Fetch Only Escalated Detections**: Enable "Create Incidents for Escalated Detections" to retrieve all escalated detections, regardless of their priority level.
    4. **Fetch Prioritized and Escalated Detections**: Enable both "Create Incidents for Prioritized Detections" and "Create Incidents for Escalated Detections". This configuration retrieves detections that are either prioritized or escalated.
9. Select the Incident Mirroring Direction:
    1. Incoming - Mirrors changes from the Vectra RUX Detection into the Cortex XSOAR incident.
    2. Outgoing - Mirrors changes from the Cortex XSOAR incident to the Vectra RUX Detection.
    3. Incoming And Outgoing - Mirrors changes both Incoming and Outgoing directions on incidents.
10. Enter the relevant tag name for mirror notes.
**Note:** This value is mapped to the dbotMirrorTags incident field in Cortex XSOAR, which defines how Cortex XSOAR handles notes when you tag them in the War Room. This is required for mirroring notes from Cortex XSOAR to Vectra RUX.
11. UnCheck the "Open Detection on Incident Reopen" option if you don't want to open the detection in Vectra when the incident is reopened in XSOAR. This option is only used when the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.
12. Select the "Detection Status for Incident Reopen" option if you want to set the detection status in Vectra when the incident is reopened in XSOAR. Default value is 'Escalated'. This option is only used when the "Open Detection on Incident Reopen" option is checked and the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.
13. UnCheck the "Close Detection on Incident Closure" option if you don't want to close the detection in Vectra when the incident is closed in XSOAR. This option is only used when the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.
14. Select the "Detection Close Reason for Incident Closure" option if you want to set the detection close reason in Vectra when the incident is closed in XSOAR. Default value is 'Benign'. This option is only used when the "Close Detection on Incident Closure" option is checked and the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.
15. Select SSL certificate validation and Proxy if required.
16. Click "Test" to validate the connection.
17. Click "Save".

**Notes for mirroring:**

* This feature is compliant with XSOAR version 6.0 and above.
* When mirroring incidents, you can make changes in Vectra that will be reflected in Cortex XSOAR, or vice versa.
* Any tags removed from the Vectra entity will not be removed in the XSOAR incident, as XSOAR doesn't allow the removal of the tags field via the backend. However, tags removed from the XSOAR incident UI will be removed from the Vectra entity.
* New notes from the XSOAR incident will be created as notes in the Vectra Detection. Updates to existing notes in the XSOAR incident will not be reflected in the Vectra Detection.
* New notes from the Vectra Detection will be created as notes in the XSOAR incident. Updates to existing notes in the Vectra Detection will create new notes in the XSOAR incident.
* If the Detection Status is updated in the Vectra Detection, it will be reflected in the XSOAR incident, or vice versa.
* If you want to reopen a detection in Vectra when the incident is reopened in XSOAR, check the "Open Detection on Incident Reopen" option. This option is only used when the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.
* Set the "Detection Status for Incident Reopen" option to set the detection status in Vectra when the incident is reopened in XSOAR. Default value is 'Escalated'. This option is only used when the "Open Detection on Incident Reopen" option is checked and the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.
* If you want to close a detection in Vectra when the incident is closed in XSOAR, check the "Close Detection on Incident Closure" option. This option is only used when the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.
* Set the "Detection Close Reason for Incident Closure" option to set the detection close reason in Vectra when the incident is closed in XSOAR. Default value is 'Benign'. This option is only used when the "Close Detection on Incident Closure" option is checked and the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.
* The mirroring settings apply only for incidents that are fetched after applying the settings.
* The mirroring is strictly tied to Incident type "Vectra RUX Events Detection" & Incoming mapper "Vectra RUX  - Incoming Mapper" If you want to change or use your custom incident type/mapper then make sure changes related to these are present.
* If you want to use the mirror mechanism and you're using custom mappers, then the incoming mapper must contain the following fields: dbotMirrorDirection, dbotMirrorId, dbotMirrorInstance, and dbotMirrorTags.
* To use a custom mapper, you must first duplicate the mapper and update the fields in the copy of the mapper. (Refer to the "Create a custom mapper consisting of the default Vectra RUX mapper" section for more information.)
* Following new fields are introduced in the response of the incident to enable the mirroring:
  * **mirror_direction:** This field determines the mirroring direction for the incident. It is a required field for XSOAR to enable mirroring support.
  * **mirror_tags:** This field determines what would be the tag needed to mirror the XSOAR entry out to Vectra RUX. It is a required field for XSOAR to enable mirroring support.
  * **mirror_instance:** This field determines from which instance the XSOAR incident was created. It is a required field for XSOAR to enable mirroring support.

For more information about this integration, visit [Vectra's knwoledge base](https://support.vectra.ai/s/article/KB-VS-1692).
