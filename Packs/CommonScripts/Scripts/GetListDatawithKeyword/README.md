Retrieve a list of dict objects that have values that contain given substring for a given list of json objects. Example: if search with keyword "test" and following list is given, 
 [
     {
     "folder": "abc",
     "username": "test"
     },
     {
     "folder": "def",
     "username": "test123"
     },
     {
     "folder": "ghi",
     "username": "admin"
     }
 ]
 then it will return first and second json objects.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | general, transformer |
| Cortex XSOAR Version | 6.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| value | The list of json objects. |
| Keyword | The substring to look for in the data. |

## Outputs

---
There are no outputs for this script.
