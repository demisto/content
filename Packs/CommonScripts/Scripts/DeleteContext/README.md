Deletes fields from context.

## Permissions

---

This automation runs using the default Limited User role, unless you explicitly change the permissions.
For more information, see the section about permissions here: For Cortex XSOAR 6, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.x/Cortex-XSOAR-Playbook-Design-Guide/Automations for Cortex XSOAR 8 Cloud, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Create-a-script for Cortex XSOAR 8 On-prem, see the https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Create-a-script.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | javascript |
| Tags | Utility |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| key | The key to delete from the context. |
| all | Whether all context will be deleted. |
| subplaybook | Whether the context key is inside of a sub-playbook. Use **auto** to delete either from the sub-playbook context (if the playbook is called as a sub-playbook) or from the global context (if the playbook is the top playbook). |
| keysToKeep | The context keys to keep when deleting all other context. Supports comma-separated values and nested objects. For example, "URL.Data" and "IP.Address". See the **Usage Notes** for more information. |
| index | The index to delete in case the 'key' argument was specified. |

## Outputs

---
There are no outputs for this script.

## Usage Notes

---

### Calling DeleteContext from Another Script

When executing DeleteContext from another script using `demisto.executeCommand('DeleteContext', args)` with the `keysToKeep` parameter set, the script will return preserved context data in the `EntryContext` field.

To ensure the preserved context data is properly maintained in the `EntryContext` field, use `return_results()`.

```javascript
// Example usage in another script
var result = demisto.executeCommand('DeleteContext', {
    'all': 'yes',
    'keysToKeep': 'URL.Data,IP.Address'
});

// Use return_results to preserve the EntryContext
return_results(result);
```

Any context keys specified in `keysToKeep` are then properly restored to the context after the deletion operation.
