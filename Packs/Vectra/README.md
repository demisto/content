# Deprecation Notice 

The Vectra content pack provided by Cortex XSOAR (named Vectra) will be deprecated in April 2023. A new version of 
the  content pack  (named [Vectra AI](https://cortex.marketplace.pan.dev/marketplace/details/Vectra_AI/))  by Vectra TME  Integrations is available in the Marketplace and those using the Cortex XSOAR (Vectra) content pack are encouraged to migrate to the currently supported Vectra AI content pack. The previous content pack will continue to function but users will need to migrate to the new content pack should support be required.

# Replacement Commands

Vectra has developed a new XSOAR content pack to replace the legacy Cortex XSOAR content pack. This new content pack includes commands that replace and extend the functionality of existing commands. The following table outlines which commands should be used for updating existing integrations.


| Legacy Command               | Replacement Command                               |
|------------------------------|---------------------------------------------------|
| `vectra-detections`          | `vectra-search-detections`                        |
| `vectra-get-detections`      | `vectra-search-detections`                        |
| `vectra-get-detection-by-id` | `vectra-detection-describe`                       |
| `vectra-hosts`               | `vectra-search-hosts`                             |
| `vectra-get-hosts`           | `vectra-search-hosts`                             |
| `vectra-get-host-by-id`      | `vectra-host-describe`                            |
| `vectra-get-users`           | `vectra-search-users`                             |
| `vectra-search`              | `vectra-search-hosts`, `vectra-search-detections` |


# New Commands

In addition to the replacement commands, new functionality is included with the current content pack. The following
table outlines the new functionality provided.

| Command                        | Command Description                                               |
|--------------------------------|-------------------------------------------------------------------|
| `vectra-search-accounts`       | Returns a list of Account objects                                 |
| `vectra-search-assignments`    | Return a list of assignments                                      |
| `vectra-search-outcomes`       | Returns a list of assignment outcomes                             |
| `vectra-account-describe`      | Returns a single Account details                                  |
| `vectra-account-add-tags`      | Add tags to an Account                                            |
| `vectra-host-del-tags`         | Delete tags from an Host                                          |
| `vectra-detection-get-pcap`    | Returns a Detection's PCAP file (if available)                    |
| `vectra-detection-markasfixed` | Marks/Unmarks a Detection as fixed by providing the Detection ID  |
| `vectra-detection-add-tags`    | Add tags to a Detection                                           |
| `vectra-detection-del-tags`    | Delete tags from a Detection                                      |
| `vectra-outcome-describe`      | Returns a single outcome details                                  |
| `vectra-outcome-create`        | Creates a new assignment outcome                                  |
| `vectra-assignment-describe`   | Returns a single assignment details                               |
| `vectra-assignment-assign`     | Assigns an Account/Host entity to a Vectra User for investigation |
| `vectra-assignment-resolve`    | Resolves an assignment by selecting resolution scheme             |

# Recommended Action
Those using the legacy Vectra content pack should review their playbooks to determine the commands that require
migration. The current content pack can support the legacy parameters for ingesting data to create incidents but it’s
most likely the user will want to expand the parameters to take advantage of the expanded support the new content
pack brings.