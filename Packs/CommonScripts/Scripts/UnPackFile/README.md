Unpacks a file using the fileName or entryID to specify a file. Files unpacked will be pushed to the War Room and names will be pushed to the context.

Supported types include, 7z (.7z), ACE (.ace), ALZIP (.alz), AR (.a), ARC (.arc), ARJ (.arj), BZIP2 (.bz2), CAB (.cab), compress (.Z), CPIO (.cpio), DEB (.deb), DMS (.dms), GZIP (.gz), LRZIP (.lrz), LZH (.lha, .lzh), LZIP (.lz), LZMA (.lzma), LZOP (.lzo), RPM (.rpm), RAR (.rar), RZIP (.rz), TAR (.tar), XZ (.xz), ZIP (.zip, .jar) and ZOO (.zoo)

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Utility, file |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| fileName | The name of the file to unpack. |
| entryID | The entry ID of the attached packed file in the War Room. |
| lastPackedFileInWarroom | The packaged file extension in the set to look for the last of its kind in the War Room. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ExtractedFiles | The list of file names which are extracted from the package. | Unknown |
