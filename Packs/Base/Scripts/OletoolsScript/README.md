This is an automation to run oletools malware analysis for office files. Oletools is a tool for analyzing Microsoft OLE2 files, such as Microsoft Office documents or Outlook messages, mainly for malware analysis, forensics and debugging. This automation allows preforminng some basic oletools commands from XSOAR. Please notice the oletools is a open source code and is subjected to changes.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.1.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| ole_command | The ole command to activate. oleid - to analyze OLE files to detect specific characteristics usually found in malicious files. oleobj - to extract embedded objects from OLE files. olevba - to extract and analyze VBA Macro source code from MS Office documents \(OLE and OpenXML\). |
| entryID | The file to activate the oletools analysis on. |
| decode | Display all the obfuscated strings with their decoded content \(Hex, Base64, StrReverse, Dridex, VBA\). NOTICE - works only with the olevba command |
| password | If encrypted office files are encountered, try decryption with this password. May be repeated. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Oletools.Oleid.ole_command_result | Indicator list from the oleid command | Unknown |
| Oletools.Oleid.file_name | File name | Unknown |
| Oletools.Oleid.sha256 | sha256 | Unknown |
| Oletools.Oleid.ole_command_result.File_format | Indicator file format | Unknown |
| Oletools.Oleid.ole_command_result.File_format.Value | Indicator file format value | Unknown |
| Oletools.Oleid.ole_command_result.File_format.Ole_Risk | Indicator file format ole risk | Unknown |
| Oletools.Oleid.ole_command_result.File_format.Description | Indicator file format Description | Unknown |
| Oletools.Oleid.ole_command_result.Container_format | Indicator container format | Unknown |
| Oletools.Oleid.ole_command_result.Container_format.Value | Indicator Container_format value | Unknown |
| Oletools.Oleid.ole_command_result.Container_format.Ole_Risk | Indicator Container_format ole risk | Unknown |
| Oletools.Oleid.ole_command_result.Container_format.Description | Indicator Container_format Description | Unknown |
| Oletools.Oleid.ole_command_result.Encrypted | Indicator Encrypted | Unknown |
| Oletools.Oleid.ole_command_result.Encrypted.Value | Indicator Encrypted value | Unknown |
| Oletools.Oleid.ole_command_result.Encrypted.Ole_Risk | Indicator Encrypted ole risk | Unknown |
| Oletools.Oleid.ole_command_result.Encrypted.Description | Indicator Encrypted Description | Unknown |
| Oletools.Oleid.ole_command_result.VBA_Macros | Indicator vba macros | Unknown |
| Oletools.Oleid.ole_command_result.VBA_Macros.Value | Indicator VBA_Macros value | Unknown |
| Oletools.Oleid.ole_command_result.VBA_Macros.Ole_Risk | Indicator VBA_Macros ole risk | Unknown |
| Oletools.Oleid.ole_command_result.VBA_Macros.Description | Indicator VBA_Macros Description | Unknown |
| Oletools.Oleid.ole_command_result.XLM_Macros | Indicator XLM_Macros | Unknown |
| Oletools.Oleid.ole_command_result.XLM_Macros.Value | Indicator XLM_Macros value | Unknown |
| Oletools.Oleid.ole_command_result.XLM_Macros.Ole_Risk | Indicator XLM_Macros ole risk | Unknown |
| Oletools.Oleid.ole_command_result.XLM_Macros.Description | Indicator XLM_Macros Description | Unknown |
| Oletools.Oleid.ole_command_result.External_Relationships | Indicator external relationships | Unknown |
| Oletools.Oleid.ole_command_result.External_Relationships.Value | Indicator XLM_Macros value | Unknown |
| Oletools.Oleid.ole_command_result.External_Relationships.Ole_Risk | Indicator XLM_Macros ole risk | Unknown |
| Oletools.Oleid.ole_command_result.External_Relationships.Description | Indicator XLM_Macros Description | Unknown |
| Oletools.Oleid.ole_command_result.ObjectPool | Indicator objectPool | Unknown |
| Oletools.Oleid.ole_command_result.ObjectPool.Value | Indicator ObjectPool value | Unknown |
| Oletools.Oleid.ole_command_result.ObjectPool.Ole_Risk | Indicator ObjectPool ole risk | Unknown |
| Oletools.Oleid.ole_command_result.ObjectPool.Description | Indicator ObjectPool Description | Unknown |
| Oletools.Oleid.ole_command_result.Flash_objects | Indicator flash objects | Unknown |
| Oletools.Oleid.ole_command_result.Flash_objects.Value | Indicator Flash_objects value | Unknown |
| Oletools.Oleid.ole_command_result.Flash_objects.Ole_Risk | Indicator Flash_objects ole risk | Unknown |
| Oletools.Oleid.ole_command_result.Flash_objects.Description | Indicator Flash_objects Description | Unknown |
| Oletools.Oleobj.ole_command_result.hyperlinkes | List of hyperLinkes | Unknown |
| Oletools.Oleobj.file_name | File name | Unknown |
| Oletools.Oleobj.sha256 | sha256 | Unknown |
| Oletools.Olevba.file_name | File name | Unknown |
| Oletools.Olevba.sha256 | sha256 | Unknown |
| Oletools.Olevba.ole_command_result.macro_analyze | macro analyze | Unknown |
| Oletools.Olevba.ole_command_result.macro_src_code | macro source code | Unknown |
| Oletools.Olevba.ole_command_result.macro_list | macro list | Unknown |
