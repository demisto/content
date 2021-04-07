Filter values with complex conditions.<br/>
You can make filters with comlex and combination conditions for the context data at any level of the tree.

---
## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | transformer, entirelist, general |


---
## Filter format examples

    [
      {
        "Description": {
          "==": "User Logged In - Failed"
        }
      },
      "or",
      [
        {
          "Description": {
            "in list": "File uploaded,File downloaded"
          }
        },
        "and",
        "not",
        {
          "DeviceName": {
            "matches any string of": "${local.TrustedDevices}"
          }
        }
      ]
    ]
