Build QRadar AQL Query. (Available from Cortex XSOAR 6.0.0).

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| base_values_to_search | The values of the first field to search. This can be a single value or a comma-separated list of values. For example admin1,admin2. |
| base_fields_to_search | The field names of the first field to search. This can be a single value or a comma-separated list of values. For example admin1,admin2. |
| base_field_state | The state of the second field to search, meaning whether the values in the field should be included or excluded. Valid options are include or exclude. |
| base_field_match | Whether the values of the second field should be an exact match or a partial match. Valid options are exact or partial. |
| select_fields | The list of fields to select within the AQL query. The default fields are DATEFORMAT\(devicetime,'dd-MM-yyyy hh:mm'\),LOGSOURCENAME\(logsourceid\),CATEGORYNAME\(category\),QIDNAME\(qid\),sourceip,destinationip,username |
| time_frame | Time frame as used in AQL examples can be LAST 7 DAYS START '2019-09-25 15:51' STOP '2019-09-25 17:51'. For more examples, view IBM's AQL documentation. |
| first_additional_values | The values of the second field to search. This can be a single value or a comma-separated list of values. For example admin1,admin2. |
| first_additional_fields | The field names of the second field to search. This can be a single value or a comma-separated list of values. For example admin1,admin2. |
| first_additional_field_state | The state of the second field to search, meaning whether the values in the field should be included or excluded. Valid options are include or exclude. |
| first_additional_field_match | Whether the values of the second field should be an exact match or a partial match. Valid options are exact or partial. |
| second_additional_values | The values of the third field to search. This can be a single value or a comma-separated list of values. For example admin1,admin2 |
| second_additional_fields | The field names of the third field to search. This can be a single value or a comma-separated list of values. For example username,user |
| second_additional_field_state | The state of the third field to search, meaning whether the values in the field should be included or excluded. Valid options are include or exclude. |
| second_additional_field_match | Whether the values of the third field should be an exact match or a partial match. Valid options are exact or partial. When choosing exact, the AQL query will use the = operator. When choosing partial, the AQL query will use ILIKE and add '%%' to the values. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| QRadarQuery | The resultant AQL query based on the inputs. | string |


## Script Example Search for a hash where we dont know the field
```!QRadarCreateAQLQuery base_field_match=partial base_values_to_search=2367666DB8DFF58982A74695760E3EF0ACEBD050```

### Context Example
```json
{
    "QRadarQuery": "select DATEFORMAT(devicetime,'dd-MM-yyyy hh:mm'),LOGSOURCENAME(logsourceid),CATEGORYNAME(category),QIDNAME(qid),sourceip,destinationip,username from events where (UTF8(payload) ILIKE '%2367666DB8DFF58982A74695760E3EF0ACEBD050%') LAST 1 HOURS"
}
```

### Human Readable Output

>select DATEFORMAT(devicetime,'dd-MM-yyyy hh:mm'),LOGSOURCENAME(logsourceid),CATEGORYNAME(category),QIDNAME(qid),sourceip,destinationip,username from events where (UTF8(payload) ILIKE '%2367666DB8DFF58982A74695760E3EF0ACEBD050%') LAST 1 HOURS

## Script Example Search for a hash in specific fields
```!QRadarCreateAQLQuery base_field_match=exact base_values_to_search=2367666DB8DFF58982A74695760E3EF0ACEBD050 base_fields_to_search=sha1,sha1-hash```

### Context Example
```json
{
    "QRadarQuery": "select DATEFORMAT(devicetime,'dd-MM-yyyy hh:mm'),LOGSOURCENAME(logsourceid),CATEGORYNAME(category),QIDNAME(qid),sourceip,destinationip,username from events where (sha1 = '2367666DB8DFF58982A74695760E3EF0ACEBD050' OR sha1-hash = '2367666DB8DFF58982A74695760E3EF0ACEBD050') LAST 1 HOURS"
}
```

### Human Readable Output

>select DATEFORMAT(devicetime,'dd-MM-yyyy hh:mm'),LOGSOURCENAME(logsourceid),CATEGORYNAME(category),QIDNAME(qid),sourceip,destinationip,username from events where (sha1 = '2367666DB8DFF58982A74695760E3EF0ACEBD050' OR sha1-hash = '2367666DB8DFF58982A74695760E3EF0ACEBD050') LAST 1 HOURS

## Script Example Search for user and hash
```!QRadarCreateAQLQuery base_field_match=exact base_values_to_search=2367666DB8DFF58982A74695760E3EF0ACEBD050 base_fields_to_search=sha1,sha1-hash first_additional_fields=username first_additional_values=admin```

### Context Example
```json
{
    "QRadarQuery": "select DATEFORMAT(devicetime,'dd-MM-yyyy hh:mm'),LOGSOURCENAME(logsourceid),CATEGORYNAME(category),QIDNAME(qid),sourceip,destinationip,username from events where (sha1 = '2367666DB8DFF58982A74695760E3EF0ACEBD050' OR sha1-hash = '2367666DB8DFF58982A74695760E3EF0ACEBD050') AND (username = 'admin') LAST 1 HOURS"
}
```

### Human Readable Output

>select DATEFORMAT(devicetime,'dd-MM-yyyy hh:mm'),LOGSOURCENAME(logsourceid),CATEGORYNAME(category),QIDNAME(qid),sourceip,destinationip,username from events where (sha1 = '2367666DB8DFF58982A74695760E3EF0ACEBD050' OR sha1-hash = '2367666DB8DFF58982A74695760E3EF0ACEBD050') AND (username = 'admin') LAST 1 HOURS

## Script Example Search for a hash in payload that doesnt contain admin
```!QRadarCreateAQLQuery base_field_match=exact base_values_to_search=2367666DB8DFF58982A74695760E3EF0ACEBD050 base_fields_to_search=sha1 first_additional_field_state=exclude first_additional_field_match=partial first_additional_values=admin```

### Context Example
```json
{
    "QRadarQuery": "select DATEFORMAT(devicetime,'dd-MM-yyyy hh:mm'),LOGSOURCENAME(logsourceid),CATEGORYNAME(category),QIDNAME(qid),sourceip,destinationip,username from events where (sha1 = '2367666DB8DFF58982A74695760E3EF0ACEBD050') AND (UTF8(payload) NOT ILIKE '%admin%') LAST 1 HOURS"
}
```

### Human Readable Output

>select DATEFORMAT(devicetime,'dd-MM-yyyy hh:mm'),LOGSOURCENAME(logsourceid),CATEGORYNAME(category),QIDNAME(qid),sourceip,destinationip,username from events where (sha1 = '2367666DB8DFF58982A74695760E3EF0ACEBD050') AND (UTF8(payload) NOT ILIKE '%admin%') LAST 1 HOURS
