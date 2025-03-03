# Vectra Detect Help

## How to get your Vectra Detect API token
To get your Vectra Detect API token you have to :
- Create a local user with a sufficient role.
- Log on the Vectra Detect UI as this local user.
- Go to "My Profile" > "General" (tab).
- Copy or generate a new token.
- Use this token directly in this integration or keep it using the Cortex XSOAR credentials store. In that case, the token should be stored in the "password" field.

## How to configure the Vectra Detect integration
To configure this integration you have to fill in the **Vectra Detect FQDN or IP** and the **API token** fields.  
*Regarding the API Token you can switch to use defined XSOAR credentials store.*  
Now if you want to tune more the integration, you can modify the others fields.

### Configuration for fetching Vectra Account or Vectra Host as a Cortex XSOAR Incident

To fetch Vectra Account or Vectra Host as a Cortex XSOAR incident:

1. Select **Fetches incidents**.
2. Under Classifier, select "Vectra Detect".
3. Under Incident type, select "N/A".
4. Under Mapper (incoming), select "Vectra Detect - Incoming Mapper" for default mapping.
5. Enter connection parameters. (Vectra Detect FQDN or IP, API Token)
6. Select SSL certificate validation and Proxy if required.
7. Update "Max created incidents per fetch" & "First fetch timestamp" based on your requirements.
8. Select the Incident Mirroring Direction:
    1. Incoming - Mirrors changes from the Vectra into the Cortex XSOAR incident.
    2. Outgoing - Mirrors changes from the Cortex XSOAR incident to the Vectra.
    3. Incoming And Outgoing - Mirrors changes both Incoming and Outgoing directions on incidents.
9. Enter the relevant tag name for mirror notes.
    **Note:** This value is mapped to the dbotMirrorTags incident field in Cortex XSOAR, which defines how Cortex XSOAR handles notes when you tag them in the War Room. This is required for mirroring notes from Cortex XSOAR to Vectra.
10. Provide the filter parameter "Tags”, to filter entities by specific tag/s for fetch type account and host.
11. Provide the filter parameter "Detection Category” and "Detection Type", to filter detections by the specified category and type for fetch type account and host.

### Fetch queries

- This integration provide 3 search queries (one per entity) in order for you to limit the events you want to fetch from Vectra Detect.
- These do not affect commands results, just the "Fetches incidents" action.
- All fetch queries (Accounts, Hosts, Detections) should be written in Lucene wording.
- During the fetch process, they are appended with "*.state:active" to get only the active events from Vectra Detect.

**Notes for mirroring:**

- The mirroring is strictly tied to incident types "Vectra Account" and "Vectra Host", as well as the incoming mapper "Vectra Detect - Incoming Mapper". If you want to change or use a custom incident type/mapper, ensure that related changes are also present.
- The mirroring settings apply only for incidents that are fetched after applying the settings.
- Any tags removed from the Vectra Account or Vectra Host will not be removed in the Cortex XSOAR incident, as Cortex XSOAR doesn't allow the removal of the tags field via the backend. However, tags removed from the Cortex XSOAR incident UI will be removed from the Vectra Account or Vectra Host.
- New notes from the Cortex XSOAR incident will be created as notes in the Vectra Account or Vectra Host. Updates to existing notes in the Cortex XSOAR incident will not be reflected in the Vectra Account or Vectra Host.
- New notes from the Vectra Account or Vectra Host will be created as notes in the Cortex XSOAR incident. Updates to existing notes in the Vectra Account or Vectra Host will create new notes in the Cortex XSOAR incident.
- If a closed Cortex XSOAR incident is tied to a specific Account or Vectra Host and new detections for that Account or Vectra Host arise or existing detections become active again, the incident will be automatically reopened.
- When a Cortex XSOAR incident is closed but there are still active detections on the Vectra side, and the Account or Vectra Host is subsequently updated, the corresponding Cortex XSOAR incident for that entity will be reopened.
- If a Cortex XSOAR incident is reopened and the corresponding entity has an assignment in Vectra, the assignment will be removed from Vectra.
- If you want to use the mirror mechanism and you're using custom mappers, then the incoming mapper must contain the following fields: dbotMirrorDirection, dbotMirrorId, dbotMirrorInstance, and dbotMirrorTags.
- To use a custom mapper, you must first duplicate the mapper and update the fields in the copy of the mapper. (Refer to the "Create a custom mapper consisting of the default Vectra Detect - Incoming Mapper" section for more information.)
- Following new fields are introduced in the response of the incident to enable the mirroring:
  - **mirror_direction:** This field determines the mirroring direction for the incident. It is a required field for Cortex XSOAR to enable mirroring support.
  - **mirror_tags:** This field determines what would be the tag needed to mirror the Cortex XSOAR entry out to Vectra. It is a required field for Cortex XSOAR to enable mirroring support.
  - **mirror_instance:** This field determines from which instance the Cortex XSOAR incident was created. It is a required field for Cortex XSOAR to enable mirroring support.
