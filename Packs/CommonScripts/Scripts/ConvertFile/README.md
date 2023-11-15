Converts a file from one format to a different format by using the convert-to function of Libre Office. For a list of supported input/output formats see:  https://wiki.openoffice.org/wiki/Framework/Article/Filter/FilterList_OOo_3_0

## Troubleshooting

### Operation not permitted

If you get an error such as:
<pre>cannot access 'soffice': Operation not permitted</pre>

Or:
<pre>/usr/bin/soffice: 191: exec: /usr/bin/oosplash: not found</pre>

You may need to upgrade **Docker**, **runc**, and the **libseccomp** rpm on your host machine.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 5.0.0 |

## Used In

---
This script is used in the following playbooks and scripts.

* Extract Indicators From File - Generic v2

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| entry_id | The War Room entryID of the file to convert. |
| format | Output format to which to convert. Can specify only file extension, such as: "pdf" or &amp;lt;ext:writer&amp;gt; such  as  "txt:Text \(Encoded\)". Default is "pdf". |
| all_files | If "yes", will return all generated files. If "no", will return only the main file. Relevant for formats that might generate multiple files, such as html \(which will generate image files additionally to the main html file\). Default is "no". |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| File.Name | The name of the output file. | String |
| File.Extension | The extension of the file. | String |
| File.EntryID | The entry ID of the file. | String |
| File.Info | Additional information about the file. | String |
| File.Type | The file type. | String |
