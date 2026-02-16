### Getting Started with Bitsight for Security Performance Management

To get started with the integration, contact Bitsight support so that your Bitsight portal can be enabled to share findings with Cortext XSOAR.

API Key: Bitsight customers can generate an API token to enable communication between Bitsight and Cortex XSOAR. Steps for generating an API token:

1) Login to Bitsight SPM at https://service.bitsighttech.com/app/spm/.
2) Click on the gear icon in top-right side.
3) In the dropdown menu, click on "Account".
4) In the "User Preferences" tab, there will be a section "API Token" to generate a new API Token.
5) Click on "Generate New Token" and use that token to authenticate the Bitsight integration in XSOAR.

Company's GUID: Each company monitored by Bitsight is identified by a unique identifier (Global Unique Identifier, or GUID). In addition, each subsidiary company associated with a parent company also has a GUID and is organized in a hierarchical tree structure.

You can specify the GUID for a parent or subsidiary company in your company tree. Any issues related to that company and its child companies in the tree structure will be retrieved. You can easily find the GUID for your parent organization by executing the following command:

"bitsight-companies-guid-get"

First fetch time in days: When running for the first time, the integration will take input from this parameter and retrieve incidents for the given number of days.

Findings Minimum Severity: This parameter helps to filter the record based on minimum severity entered here. You can choose one of the severity listed.

Findings Minimum Asset Category: This parameter helps to filter the record based on the minimum asset category entered here. You can choose one of the asset categories listed.

Mirroring Direction: The mirroring direction in which to mirror the findings. You can mirror "Incoming" (from Bitsight to XSOAR), "Outgoing" (from XSOAR to Bitsight), or in both directions. This parameter enables bidirectional synchronization of incident data between Bitsight and Cortex XSOAR.

Mirror Tag for Notes: The tag value should be used to mirror XSOAR incident notes to Bitsight finding comments by adding the same tag in the notes. This parameter is required when the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.

Bitsight User Email Address: Provide the Bitsight user email address to be used for sending XSOAR incident notes as Bitsight finding comments. This parameter is required when the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.

Bitsight Remediation Status for Incident Opening: Remediation status to set in Bitsight when opening incidents in XSOAR. Default value is 'Open'. Available options are 'Open' and 'Work In Progress'. This parameter is only used when the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.

Reopen incident based on Bitsight Remediation Status: If selected, closed incidents will be reopened in XSOAR when finding remediation status on Bitsight platform matches the configured 'Remediation Status for Incident Opening'. This parameter is only used when the mirroring direction is set to 'Incoming' or 'Incoming And Outgoing'.

Bitsight Remediation Status for Incident Closure: Remediation status to set in Bitsight when closing incidents in XSOAR. Default value is 'Resolved'. Available options are 'Resolved' and 'Risk Accepted'. This parameter is only used when the mirroring direction is set to 'Outgoing' or 'Incoming And Outgoing'.

Close incident based on Bitsight Remediation Status: If selected, active incidents will be closed in XSOAR when finding remediation status on Bitsight platform matches the configured 'Remediation Status for Incident Closure'. This parameter is only used when the mirroring direction is set to 'Incoming' or 'Incoming And Outgoing'.

Findings Affect Rating Reason: This parameter helps to filter the record based on Affect Rating Reason. You can choose multiple affect rating reasons listed.

Findings Grade: This parameter helps to filter the record based on Grade. You can choose multiple grades listed.

Risk Vector: Parameter helps to filter the record based on Risk Vector. By default, 'All' will be selected, if you need only particular values you can unselect 'All' and select the required values listed.

Note: Please be sure to click on 'Reset the "last run" timestamp', when changing the values of parameters 'First fetch time in days', 'Findings Affect Rating Reason','Findings Minimum Severity', 'Findings Minimum Asset Category', 'Findings Grade' or 'Risk Vector' after fetching has started to avoid dropping of findings.

### Notes for mirroring

- This feature is compliant with XSOAR version 6.1.0 and above.
- When mirroring incidents, you can make changes in Bitsight that will be reflected in Cortex XSOAR, or vice versa.
- The mirroring direction can be set to "Incoming" (from Bitsight to XSOAR), "Outgoing" (from XSOAR to Bitsight), or "Incoming And Outgoing" for bidirectional synchronization.
- New notes from the Cortex XSOAR incident will be created as comments in the Bitsight findings. Updates to existing notes in the Cortex XSOAR incident will not be reflected in the Bitsight findings.
- New comments from the Bitsight findings will be created as notes in the Cortex XSOAR incident. Updates to existing comments in the Bitsight findings will create new notes in the Cortex XSOAR incident.
- When outgoing mirroring is enabled, the remediation status in Bitsight will be updated based on the Remediation status parameter in XSOAR:
  - Opening incidents in XSOAR will set the remediation status in Bitsight according to the "Bitsight Remediation Status for Incident Opening" parameter (default: "Open").
  - Closing incidents in XSOAR will set the remediation status in Bitsight according to the "Bitsight Remediation Status for Incident Closure" parameter (default: "Resolved").
- If an active Cortex XSOAR incident is tied to a specific BitSight finding, and the finding's remediation status matches the "Bitsight Remediation Status for Incident Closure" parameter:
  - If the "Reopen incident based on BitSight Remediation Status" parameter is selected and "Incoming Mirroring" is enabled, the incident will be closed in XSOAR.
- If a closed Cortex XSOAR incident is tied to a specific BitSight finding, and the finding's remediation status matches the "Bitsight Remediation Status for Incident Opening" parameter:
  - If the "Reopen incident based on BitSight Remediation Status" parameter is selected and "Incoming Mirroring" is enabled, the incident will be reopened in XSOAR.
- The mirroring settings apply only for incidents that are fetched after applying the settings.
- The mirroring is strictly tied to Incident type "BitSight Findings" & Incoming mapper "BitSight - Incoming Mapper". If you want to change or use your custom incident type/mapper then make sure changes related to these are present.
- If you want to use the mirror mechanism and you're using custom mappers, then the incoming mapper must contain the following fields: dbotMirrorDirection, dbotMirrorId, dbotMirrorInstance, and dbotMirrorTags.
- Following new fields are introduced in the response of the incident to enable the mirroring:
  - **mirror_direction:** This field determines the mirroring direction for the incident. It is a required field for XSOAR to enable mirroring support.
  - **mirror_tags:** This field determines what would be the tag needed to mirror the Cortex XSOAR entry out to Bitsight. It is a required field for XSOAR to enable mirroring support.
  - **mirror_instance:** This field determines from which instance the XSOAR incident was created. It is a required field for XSOAR to enable mirroring support.

### Troubleshooting

The following are tips for handling issues with mirroring incidents between Bitsight and Cortex XSOAR.

| **Issue** | **Recommendation** |
| --- | --- |
| Mirroring is not working. | Open Context Data and search for dbot. Confirm the dbot fields are configured correctly either through the mapper for that specific incident type or using setIncident. Specifically, make sure the integration instance is configured correctly for the mirroring direction (incoming, outgoing, both) - dbotMirrorId, dbotMirrorDirection, dbotMirrorInstance, dbotMirrorTags.|
| Required fields are not getting sent or not visible in UI. | This may be a mapping issue, specifically if you have used a custom mapper make sure you've covered all the out of box mapper fields. |
| Notes from Cortex XSOAR have not been mirrored in Bitsight | Tag is required for mirroring notes from Cortex XSOAR to Bitsight. There might be a reason the note is not tagged as the tag needs to be added manually in Cortex XSOAR.<br>Click **Actions** > **Tags** and add the "note" tag (OR the specific tag name which was set up in the Instance Configuration).|
| Server experiencing high load due to mirroring. | Consider increasing the mirroring interval to reduce server load. The default mirroring interval is 1 minute, which can be adjusted by updating the `sync.mirror.job.delay` field in the Integration Server Configuration to a higher value based on your server capacity and requirements. For more information, see [Integration Server Configurations (XSOAR 6.x)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.14/Cortex-XSOAR-Administrator-Guide/Integration-Server-Configurations) or [Server Configurations (XSOAR 8.x)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-SaaS-Documentation/Server-configurations). |
