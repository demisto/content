This is an automation to run oletools malware analysis for office files. Oletools is a tool
for analyzing Microsoft OLE2 files,
such as Microsoft Office documents or Outlook messages, mainly for malware analysis,
forensics, and debugging.
Note that oletools is open source code and is subject to change.

## Script Data
---

| **Name** | **Description** |
| --- |-----------------|
| Script Type | python3         |
| Cortex XSOAR Version | 6.5.0           |

## Inputs
---

| **Argument Name** | **Description**                                                                                                                                                                                                                                                                                                |
| --- |----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| ole_command | The OLE command to activate.<br/>- oleid - to analyze OLE files to detect specific characteristics usually found in malicious files.<br/>- oleobj - to extract embedded objects from OLE files. <br/>- olevba- to extract and analyze VBA Macro source code from MS Office documents \(OLE and OpenXML\).<br/> |
| entryID | The file to activate the oletools analysis on.                                                                                                                                                                                                                                                                 |
| decode | Display all the obfuscated strings with their decoded content \(Hex, Base64, StrReverse, Dridex, VBA\). Note that this works only with the olevba command                                                                                                                                                      |
| password | If encrypted office files are encountered, try decryption with this password. May be repeated.                                                                                                                                                                                                                 |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Oletools.Oleid.ole_command_result | Indicator list from the oleid command. | Unknown |
| Oletools.Oleid.file_name | File name | Unknown |
| Oletools.Oleid.sha256 | SHA256 hash. | Unknown |
| Oletools.Oleid.ole_command_result.File_format | Indicator file format. | Unknown |
| Oletools.Oleid.ole_command_result.File_format.Value | Indicator file format value. | Unknown |
| Oletools.Oleid.ole_command_result.File_format.Ole_Risk | Indicator file format OLE risk. | Unknown |
| Oletools.Oleid.ole_command_result.File_format.Description | Indicator file format description. | Unknown |
| Oletools.Oleid.ole_command_result.Container_format | Indicator container format. | Unknown |
| Oletools.Oleid.ole_command_result.Container_format.Value | Indicator container format value | Unknown |
| Oletools.Oleid.ole_command_result.Container_format.Ole_Risk | Indicator container format OLE risk. | Unknown |
| Oletools.Oleid.ole_command_result.Container_format.Description | Indicator container format description. | Unknown |
| Oletools.Oleid.ole_command_result.Encrypted | Indicator encrypted. | Unknown |
| Oletools.Oleid.ole_command_result.Encrypted.Value | Indicator encrypted value. | Unknown |
| Oletools.Oleid.ole_command_result.Encrypted.Ole_Risk | Indicator encrypted OLE risk. | Unknown |
| Oletools.Oleid.ole_command_result.Encrypted.Description | Indicator encrypted description. | Unknown |
| Oletools.Oleid.ole_command_result.VBA_Macros | Indicator VBA macros. | Unknown |
| Oletools.Oleid.ole_command_result.VBA_Macros.Value | Indicator VBA macros value. | Unknown |
| Oletools.Oleid.ole_command_result.VBA_Macros.Ole_Risk | Indicator VBA macros OLE risk. | Unknown |
| Oletools.Oleid.ole_command_result.VBA_Macros.Description | Indicator VBA macros description. | Unknown |
| Oletools.Oleid.ole_command_result.XLM_Macros | Indicator XLM macros. | Unknown |
| Oletools.Oleid.ole_command_result.XLM_Macros.Value | Indicator XLM macros value. | Unknown |
| Oletools.Oleid.ole_command_result.XLM_Macros.Ole_Risk | Indicator XLM macros OLE risk. | Unknown |
| Oletools.Oleid.ole_command_result.XLM_Macros.Description | Indicator XLM macros description. | Unknown |
| Oletools.Oleid.ole_command_result.External_Relationships | Indicator external relationships. | Unknown |
| Oletools.Oleid.ole_command_result.External_Relationships.Value | Indicator XLM macros value. | Unknown |
| Oletools.Oleid.ole_command_result.External_Relationships.Ole_Risk | Indicator XLM macros OLE risk. | Unknown |
| Oletools.Oleid.ole_command_result.External_Relationships.Description | Indicator XLM macros description. | Unknown |
| Oletools.Oleid.ole_command_result.ObjectPool | Indicator object pool. | Unknown |
| Oletools.Oleid.ole_command_result.ObjectPool.Value | Indicator object pool value. | Unknown |
| Oletools.Oleid.ole_command_result.ObjectPool.Ole_Risk | Indicator object pool OLE risk. | Unknown |
| Oletools.Oleid.ole_command_result.ObjectPool.Description | Indicator object pool description. | Unknown |
| Oletools.Oleid.ole_command_result.Flash_objects | Indicator flash objects. | Unknown |
| Oletools.Oleid.ole_command_result.Flash_objects.Value | Indicator flash objects value. | Unknown |
| Oletools.Oleid.ole_command_result.Flash_objects.Ole_Risk | Indicator flash objects OLE risk. | Unknown |
| Oletools.Oleid.ole_command_result.Flash_objects.Description | Indicator flash objects description. | Unknown |
| Oletools.Oleobj.ole_command_result.hyperlinks | List of hyperlinks. | Unknown |
| Oletools.Oleobj.file_name | File name. | Unknown |
| Oletools.Oleobj.sha256 | SHA256 hash. | Unknown |
| Oletools.Olevba.file_name | File name. | Unknown |
| Oletools.Olevba.sha256 | SHA256 hash. | Unknown |
| Oletools.Olevba.ole_command_result.macro_analyze | Macro analyze. | Unknown |
| Oletools.Olevba.ole_command_result.macro_src_code | Macro source code. | Unknown |
| Oletools.Olevba.ole_command_result.macro_list | Macro list. | Unknown |
