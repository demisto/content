Generate a compliance report for Prisma Cloud resources - host, container or image.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Cortex XSOAR Version | 6.10.0 |

## Dependencies

---
This script uses the following commands and scripts.

* send-mail
* ExportToXLSX
* ConvertTableToHTML

## Inputs

---

| **Argument Name** | **Description**                                                                                                                                                                           |
| --- |-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| table | The table of data.                                                                                                                                                                        |
| title | The title of the report.                                                                                                                                                                  |
| to | The to email address.                                                                                                                                                                     |
| headers | The headers for the HTML table.                                                                                                                                                           |
| resource_type | The resource type.                                                                                                                                                                        |
| output_type | Whether to send the compliance issues as an html table or attached in xlsx file.                                                                                                          |
| desired_severities | A comma-separated list of severities which will be included in the compliance report. If no value is provided, all of the severities will be included. Example: "Critical, High"."        |
| desired_resources | A comma-separated list of resources. In case the report should contain results only for specific resources, whether it's a host, container ID or an image ID, provide the resources here. |

## Outputs

---
There are no outputs for this script.
