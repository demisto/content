### Securonix Integration
Use Securonix Integration to identify and prioritize Security Incidents and Threats across the organization. This integration allows the security teams to synchronize the Securonix Incidents and Threats with Cortex XSOAR in real time making it feasible to manage operations from a single place.  

This integration supports both cloud and on-prem v6.4 Feb 2023 R3 instances of Securonix.
- To configure a cloud base instance use the *Tenant* parameter only.
- To configure an on-prem instance, use both the *Host* and *Tenant* parameters.


### Instance Configuration
The integration supports two types of ingestion:
1. Securonix Incident: Fetches Securonix Incident as an XSOAR Incident
2. Securonix Threat: Fetches Securonix Threat as an XSOAR Incident


#### Securonix Incident

To fetch Securonix Incident follow the next steps:
1. Select Fetches incidents.
2. Under Classifier, select "N/A".
3. Under Incident type, select "Securonix Incident".
4. Under Mapper (incoming), select "Securonix Incident - Incoming  Mapper" for default mapping.
5. Under Type of entity to fetch, select "Incident".
6. Enter the connection parameters. (Host, Tenant, Username & Password)
7. Select the "Incidents to fetch":
    1. all - This will fetch incidents updated in the given time range. 
    2. opened - This will fetch incidents created in the given time range.
    3. closed - This will fetch incidents closed in the given time range.
8. Update "Set default incident severity", "First Fetch time range" & "Max Fetch Count" based on your requirement.
9. Select the Incident Mirroring Direction:
    1. Incoming - Mirrors changes from the Securonix incident into the Cortex XSOAR incident.
    2. Outgoing - Mirrors changes from the Cortex XSOAR incident to the Securonix incident.
    3. Incoming And Outgoing - Mirrors changes both Incoming and Outgoing directions on incidents.
    4. None - Turns off incident mirroring.
10. Enter the relevant values for "State" & "Action" values for mirroring.
     - Below table indicates which fields are required for the respective mirroring type.

| **Mirroring Type** | **Securonix workflow States for Incoming mirroring** | **Securonix State for XSOAR Active State** | **Securonix Action for XSOAR Active Action** | **Securonix State for XSOAR Closed State** | **Securonix Action for XSOAR Closed Action** | 
| --- | --- | --- | --- | --- | --- | 
| Incoming | Yes | No | No | No | No | 
| Outgoing | No | Yes | Yes | Yes | Yes | 
| Incoming and Outgoing | Yes | Yes | Yes | Yes | Yes |
 
10. Enter the relevant Comment Entry Tag.  
**Note**: This value is mapped to the **dbotMirrorTags** incident field in Cortex XSOAR, which defines how Cortex XSOAR handles comments when you tag them in the War Room. This is required for mirroring comments from Cortex XSOAR to Securonix.
11. Optional: Check the "Close respective Securonix incident after fetching" parameter, if you want to close the Securonix Incident once it is fetched in the XSOAR.
    Below Parameters are required if this option is checked:
    - Securonix action name for XSOAR's active state for Outgoing
    - Securonix status for XSOAR's active state for Outgoing
    - Securonix action name for XSOAR's close state for Outgoing
    - Securonix status for XSOAR's close state for Outgoing
12. Enter the relevant values for Securonix Retry parameters "Count", "Delay" & "Delay Type".

**Notes for mirroring:**

- The mirroring settings apply only for incidents that are fetched after applying the settings. Pre-existing comments are not fetched/mirrored at the time of incident creation.
- For mirroring to work flawlessly, a three-state workflow(similar to XSOAR) must be configured on the Securonix Incident side.
- The mirroring is strictly tied to Incident type "Securonix Incident" & Incoming mapper "Securonix Incident - Incoming Mapper" if you want to change or use your custom incident type/mapper then make sure changes related to these are present.
- If you want to use the mirror mechanism and you're using custom mappers, then the incoming mapper must contain the following fields: dbotMirrorDirection, dbotMirrorId, dbotMirrorInstance, dbotMirrorTags and securonixcloseincident.
- To use a custom mapper, you must first duplicate the mapper and update the fields in the copy of the mapper. If you detach the out-of-the-box mapper and make changes to it, the pack does not automatically get updates.
- If you are using a custom incident type, you also need to create custom corresponding incoming mappers.
- Following new fields are introduced in the response of the incident to enable the mirroring:
  - **mirror_direction**: This field determines the mirroring direction for the incident. It is a required field for XSOAR to enable mirroring support.
  - **mirror_tags**: This field determines what would be the tag needed to mirror the XSOAR entry out to Securonix. It is a required field for XSOAR to enable mirroring support.
  - **mirror_instance**: This field determines from which instance the XSOAR incident was created. It is a required field for XSOAR to enable mirroring support.
  - **close_sx_incident**: This field determines whether to close the respective Securonix incident once fetched in the XSOAR based on the instance configuration. It is required for closing the respective incident on Securonix. This will be used in the playbook to close the securonix incident.



#### Securonix Threat
To fetch Securonix Threat follow the next steps:
1. Select Fetches incidents.
2. Under Classifier, select "N/A".
3. Under Incident type, select Securonix Threat.
4. Under Mapper (incoming), select Securonix Threat - Incoming Mapper for default mapping.
5. Under Type of entity to fetch, select Threat.
6. Enter the Tenant Name in case of MSSP user.
7. Enter the connection parameters. (Host, Tenant, Username & Password)
8. Enter the "The maximum number of incidents to fetch each time". The recommended number of threats to fetch is 100 considering the API implications, although 200 is allowed.
9. Enter the relevant values for Securonix Retry parameters "Count", "Delay" & "Delay Type".
