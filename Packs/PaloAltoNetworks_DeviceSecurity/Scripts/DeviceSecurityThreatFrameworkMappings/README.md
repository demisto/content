Displays MITRE ATT&CK Enterprise and ICS technique mappings and IEC 62443 references in a dynamic incident layout section.

The script reads the **Device Security MITRE Mappings Raw** (`devicesecuritymitremappingsraw`) and **Device Security IEC References** (`devicesecurityiecreferences`) incident fields. It accepts structured or JSON-encoded data, groups techniques by framework, and removes duplicate rows. Missing mappings or references display `N/A`.

This script runs in the incident context and has no arguments or context outputs.
