Makes an HTML indicator table using the FancyEmail integration

### Example: Sending an email with an Indicator Table
_Scenario: Send an email containing an email with a table of malicious URLs linked to an incident. Use the alt link format, to use a seperate text area to link to the indicator rather than using the indicator name/value._

From within an incident:
```
!MakeFancyEMailIndicatorTable query="incident.id=${incident.id} verdict=Malicious type:URL" use_alt_link=True max_name_chars=40
```

This outputs to the FancyEmails.IndicatorTable.html context the raw_html for the table. You can embed it into a fancy email by:
```
!SendFancyEmail to=me@mycompany.com subject="Check Out These Malicious Indicators" html_body=${FancyEmails.IndicatorTable.html} body_header="Malicious Indicators related to ${incident.id}" banner="Classified" 
```

## Script Data


| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Dependencies

This script uses the following commands and scripts.
* fancy-email-make-table

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| query | Query to use when fetching indicators |
| name | Name of the Table for the header and context |
| use_alt_link | Create a link to the indicator in a separate column, rather than turning the name to a link. \(Use for Domain, URL, and IP like indicators\) |
| max_name_characters | Max characters to use in the name field before truncating |

## Outputs
---
There are no outputs for this script.
